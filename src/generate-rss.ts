import { Feed } from "feed";
import path from "path";
import * as fs from "fs/promises";
import { convertJsonToOPML } from "./toOPML.ts";
import {
    ECOSYSTEM_FEEDS,
    CLASSIFICATION_FEEDS
} from "./RSS_FEEDS.ts";

// @ts-expect-error - subpath import from CJS package without exports field
import type {
    SecurityAdvisoryEcosystem,
    SecurityAdvisoryClassification
} from "@octokit/graphql-schema/schema";

import { graphql } from "@octokit/graphql";
import { createMarkdown } from "safe-marked";
import dayjs from "dayjs";

type SecurityAdvisoryReference = {
    url: string;
};

type VulnerabilityVersionInfo = {
    packageName: string;
    ecosystem?: string;
    vulnerableVersionRange: string;
    firstPatchedVersion: string | null;
};

type SecurityVulnerabilityConnection = {
    nodes?: Array<{
        package: {
            name: string;
        };
        advisory: {
            summary: string;
            description: string;
            references: SecurityAdvisoryReference[];
            permalink: string;
            updatedAt: string;
            publishedAt: string;
        };
        severity: string;
        updatedAt: string;
        vulnerableVersionRange: string;
        firstPatchedVersion: {
            identifier: string;
        } | null;
    } | null> | null;
};

type SecurityAdvisoryConnection = {
    nodes?: Array<{
        summary: string;
        description: string;
        references: SecurityAdvisoryReference[];
        permalink: string;
        updatedAt: string;
        publishedAt: string;
        severity: string;
        vulnerabilities: {
            nodes?: Array<{
                package: {
                    name: string;
                    ecosystem: string;
                };
                vulnerableVersionRange: string;
                firstPatchedVersion: {
                    identifier: string;
                } | null;
            } | null> | null;
        };
    } | null> | null;
};

const escapeHtml = (s: string) =>
    s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");

/**
 * Build an HTML table of affected / patched versions.
 * Version ranges contain "<" and ">", so everything is escaped.
 */
const createVersionsHTML = (versions: VulnerabilityVersionInfo[]) => {
    if (!versions.length) {
        return "";
    }

    const rows = versions
        .map(
            (v) => `<tr>
<td>${escapeHtml(v.packageName)}${
                v.ecosystem ? ` (${escapeHtml(v.ecosystem)})` : ""
            }</td>
<td><code>${escapeHtml(v.vulnerableVersionRange || "unknown")}</code></td>
<td>${
                v.firstPatchedVersion
                    ? `<code>${escapeHtml(v.firstPatchedVersion)}</code>`
                    : "No fix available"
            }</td>
</tr>`
        )
        .join("\n");

    return `<h3>Affected versions</h3>
<table>
<thead><tr><th>Package</th><th>Vulnerable versions</th><th>Patched version</th></tr></thead>
<tbody>
${rows}
</tbody>
</table>
`;
};

const createBody = (
    descriptionMarkdown: string,
    references: SecurityAdvisoryReference[],
    versions: VulnerabilityVersionInfo[] = []
) => {
    const md = createMarkdown();

    const referencesMD = references.length
        ? "\n### References\n\n" +
          references
              .map((ref) => `- <${ref.url}>`)
              .join("\n")
        : "";

    return createVersionsHTML(versions) + md(descriptionMarkdown + referencesMD);
};

type Item = {
    url: string;
    title: string;
    createdAt: string;
    updatedAt: string;
    severity: string;
    author: {
        avatarUrl: string;
        login: string;
        url: string;
    };
    versions: VulnerabilityVersionInfo[];
    bodyHTML: string;
};

export type GenerateRSSOptions = {
    title: string;
    description: string;
    link: string;
    homepage?: string;
    image?: string;
    favicon?: string;
    updated: Date;
    filter?: (item: Item) => boolean;
};

/**
 * Search GitHub Security Vulnerabilities by ecosystem.
 */
export const search = ({
    ecosystem,
    GITHUB_TOKEN,
    SIZE = 20
}: {
    ecosystem: SecurityAdvisoryEcosystem;
    GITHUB_TOKEN: string;
    SIZE: number;
}): Promise<Item[]> => {
    return graphql<{
        securityVulnerabilities: SecurityVulnerabilityConnection;
    }>(
        `
            query ($ECOSYSTEM: SecurityAdvisoryEcosystem!, $SIZE: Int!) {
                securityVulnerabilities(
                    ecosystem: $ECOSYSTEM,
                    first: $SIZE
                ) {
                    nodes {
                        package {
                            name
                        }
                        advisory {
                            summary
                            description
                            references {
                                url
                            }
                            permalink
                            updatedAt
                            publishedAt
                        }
                        severity
                        updatedAt
                        vulnerableVersionRange
                        firstPatchedVersion {
                            identifier
                        }
                    }
                }
            }
        `,
        {
            ECOSYSTEM: ecosystem,
            SIZE,
            headers: {
                authorization: `token ${GITHUB_TOKEN}`
            }
        }
    ).then((res) => {
        const nodes = res.securityVulnerabilities.nodes ?? [];

        return nodes.map((node) => {
            if (!node) {
                throw new Error("Non node");
            }

            const versions: VulnerabilityVersionInfo[] = [
                {
                    packageName: node.package.name,
                    vulnerableVersionRange: node.vulnerableVersionRange,
                    firstPatchedVersion:
                        node.firstPatchedVersion?.identifier ?? null
                }
            ];

            return {
                url: node.advisory.permalink,
                title: `[${node.package.name}] ${node.advisory.summary}`,
                createdAt: node.advisory.publishedAt,
                updatedAt: node.advisory.updatedAt,
                severity: node.severity,
                author: {
                    // FIXME: want to use published account
                    avatarUrl: "",
                    login: "GitHub",
                    url: node.advisory.permalink
                },
                versions,
                bodyHTML: createBody(
                    node.advisory.description,
                    node.advisory.references,
                    versions
                )
            } as Item;
        });
    });
};

/**
 * Search GitHub Security Advisories by classification.
 * Used for feeds such as MALWARE.
 */
export const searchByClassification = ({
    classification,
    GITHUB_TOKEN,
    SIZE = 20
}: {
    classification: SecurityAdvisoryClassification;
    GITHUB_TOKEN: string;
    SIZE: number;
}): Promise<Item[]> => {
    return graphql<{
        securityAdvisories: SecurityAdvisoryConnection;
    }>(
        `
            query (
                $CLASSIFICATIONS: [SecurityAdvisoryClassification!]!,
                $SIZE: Int!
            ) {
                securityAdvisories(
                    classifications: $CLASSIFICATIONS,
                    first: $SIZE
                ) {
                    nodes {
                        summary
                        description
                        references {
                            url
                        }
                        permalink
                        updatedAt
                        publishedAt
                        severity
                        vulnerabilities(first: 10) {
                            nodes {
                                package {
                                    name
                                    ecosystem
                                }
                                vulnerableVersionRange
                                firstPatchedVersion {
                                    identifier
                                }
                            }
                        }
                    }
                }
            }
        `,
        {
            CLASSIFICATIONS: [classification],
            SIZE,
            headers: {
                authorization: `token ${GITHUB_TOKEN}`
            }
        }
    ).then((res) => {
        const nodes = res.securityAdvisories.nodes ?? [];

        return nodes.map((node) => {
            if (!node) {
                throw new Error("Non node");
            }

            const versions: VulnerabilityVersionInfo[] = (
                node.vulnerabilities?.nodes ?? []
            )
                .filter((v): v is NonNullable<typeof v> => v !== null)
                .map((v) => ({
                    packageName: v.package.name,
                    ecosystem: v.package.ecosystem,
                    vulnerableVersionRange: v.vulnerableVersionRange,
                    firstPatchedVersion:
                        v.firstPatchedVersion?.identifier ?? null
                }));

            return {
                url: node.permalink,
                title: `[${classification}] ${node.summary}`,
                createdAt: node.publishedAt,
                updatedAt: node.updatedAt,
                severity: node.severity,
                author: {
                    avatarUrl: "",
                    login: "GitHub",
                    url: node.permalink
                },
                versions,
                bodyHTML: createBody(
                    node.description,
                    node.references,
                    versions
                )
            } as Item;
        });
    });
};

/**
 * Generate JSON Feed or Atom Feed.
 */
export const generateRSS = (
    items: Item[],
    options: GenerateRSSOptions
) => {
    const feed = new Feed({
        title: options.title,
        description: options.description,
        id: options.link,
        link: options.homepage || options.link,
        feedLinks: {
            json: options.link
        },
        image: options.image,
        favicon: options.favicon,
        copyright: "github-advisory-database-rss",
        updated: options.updated,
        generator: "github-advisory-database-rss"
    });

    feed.addCategory("CRITICAL");
    feed.addCategory("HIGH");
    feed.addCategory("MODERATE");
    feed.addCategory("LOW");

    const filter = options.filter;
    const filteredItems = filter
        ? items.filter((item) => filter(item))
        : items;

    filteredItems.forEach((item) => {
        const body = item.bodyHTML ?? "";

        const image = item.author.avatarUrl
            ? `<img src="${item.author.avatarUrl}" width="64" height="64" alt=""/><br/>`
            : "";

        feed.addItem({
            title: item.title,
            content: image + body,
            link: item.url,
            category: [
                {
                    term: item.severity,
                    name: "severity"
                }
            ],
            author: [
                {
                    name: item.author.login,
                    link: item.author.url,
                    email: `${item.author.login}@noreply.github.com`
                }
            ],
            published: dayjs(item.createdAt).toDate(),
            date: dayjs(item.updatedAt).toDate()
        });
    });

    if (path.extname(options.link) === ".json") {
        return feed.json1();
    }

    return feed.atom1();
};

export type RSSItem = {
    query: string;
    SIZE?: number;
} & Omit<GenerateRSSOptions, "updated" | "description">;

/**
 * Generate all RSS feeds.
 */
if (import.meta.main) {
    const distDir = path.join(import.meta.dirname, "../dist");
    const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

    if (!GITHUB_TOKEN) {
        throw new Error("env.GITHUB_TOKEN required");
    }

    (async function () {
        await fs.mkdir(distDir, {
            recursive: true
        });

        // ---------------------------------------------
        // 1. Generate ecosystem feeds
        // ---------------------------------------------
        for (const rssFeed of ECOSYSTEM_FEEDS) {
            try {
                const { ecosystem, ...options } = rssFeed;

                const items = await search({
                    ecosystem,
                    GITHUB_TOKEN,
                    SIZE: 20
                });

                const description = `${rssFeed.title} on GitHub`;

                const jsonRSS = generateRSS(items, {
                    ...options,
                    description,
                    updated: new Date()
                });

                const atomRSS = generateRSS(items, {
                    ...options,
                    link: rssFeed.link.replace(/\.json$/, ".rss"),
                    description,
                    updated: new Date()
                });

                const filename = path.basename(
                    rssFeed.link,
                    ".json"
                );

                await fs.writeFile(
                    path.join(distDir, filename + ".json"),
                    jsonRSS,
                    "utf-8"
                );

                await fs.writeFile(
                    path.join(distDir, filename + ".rss"),
                    atomRSS,
                    "utf-8"
                );

                console.log(`Generated ecosystem feed: ${ecosystem}`);
            } catch (error) {
                console.error(
                    `Error on ecosystem ${rssFeed.ecosystem}`,
                    error
                );

                console.log("But continue to next");
            }
        }

        // ---------------------------------------------
        // 2. Generate classification feeds (e.g. MALWARE)
        // ---------------------------------------------
        for (const rssFeed of CLASSIFICATION_FEEDS) {
            try {
                const { classification, ...options } = rssFeed;

                const items = await searchByClassification({
                    classification,
                    GITHUB_TOKEN,
                    SIZE: 20
                });

                const description = `${rssFeed.title} on GitHub`;

                const jsonRSS = generateRSS(items, {
                    ...options,
                    description,
                    updated: new Date()
                });

                const atomRSS = generateRSS(items, {
                    ...options,
                    link: rssFeed.link.replace(/\.json$/, ".rss"),
                    description,
                    updated: new Date()
                });

                const filename = path.basename(
                    rssFeed.link,
                    ".json"
                );

                await fs.writeFile(
                    path.join(distDir, filename + ".json"),
                    jsonRSS,
                    "utf-8"
                );

                await fs.writeFile(
                    path.join(distDir, filename + ".rss"),
                    atomRSS,
                    "utf-8"
                );

                console.log(
                    `Generated classification feed: ${classification}`
                );
            } catch (error) {
                console.error(
                    `Error on classification ${rssFeed.classification}`,
                    error
                );

                console.log("But continue to next");
            }
        }

        // ---------------------------------------------
        // 3. Generate OPML
        // ---------------------------------------------
        const opml = convertJsonToOPML([
            ...ECOSYSTEM_FEEDS,
            ...CLASSIFICATION_FEEDS
        ]);

        await fs.writeFile(
            path.join(distDir, "index.opml"),
            opml,
            "utf-8"
        );

        // ---------------------------------------------
        // 4. Generate index.html
        // ---------------------------------------------
        const ecosystemLinks = ECOSYSTEM_FEEDS.map((feed) => {
            return `<li>
                <code>${feed.ecosystem}</code>:
                <a href="${feed.link}">${feed.link}</a>
                (<a href="${feed.link.replace(/\.json$/, ".rss")}">atom</a>)
            </li>`;
        }).join("\n");

        const classificationLinks = CLASSIFICATION_FEEDS.map((feed) => {
            return `<li>
                <code>${feed.classification}</code>:
                <a href="${feed.link}">${feed.link}</a>
                (<a href="${feed.link.replace(/\.json$/, ".rss")}">atom</a>)
            </li>`;
        }).join("\n");

        const index = {
            html: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>RSS Feeds for GitHub Advisory Database</title>
    <meta name="description" content="RSS Feeds for GitHub Advisory Database" />
</head>
<body>
<a href="https://github.com/prajeetguha/github-advisory-database-rss">
    <img
        style="position: absolute; top: 0; right: 0; border: 0;"
        src="https://github.blog/wp-content/uploads/2008/12/forkme_right_darkblue_121621.png"
        alt="Fork me on GitHub"
    >
</a>

<p>
    These RSS Feeds are a collection of
    <a href="https://github.com/advisories">GitHub Advisory Database</a>.
</p>

<p>Supported Feed types</p>
<ul>
    <li>JSON Feed</li>
    <li>Atom Feed</li>
</ul>

<p>
    OPML Feeds (all ecosystems):
    <a href="./index.opml">
        https://prajeetguha.github.io/github-advisory-database-rss/index.opml
    </a>
</p>

<h3>Ecosystem Feeds</h3>
<ul>
${ecosystemLinks}
</ul>

<h3>Classification Feeds</h3>
<ul>
${classificationLinks}
</ul>

<footer>
    <a href="https://github.com/prajeetguha/github-advisory-database-rss">
        Source Code
    </a>
</footer>
</body>
</html>
`
        };

        await fs.writeFile(
            path.join(distDir, "index.html"),
            index.html,
            "utf-8"
        );

        console.log("RSS feed generation completed.");

    })().catch((error) => {
        console.error(error);
        process.exit(1);
    });
}
