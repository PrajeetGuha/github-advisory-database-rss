// @ts-expect-error - subpath import from CJS package without exports field
import type { SecurityAdvisoryEcosystem, SecurityAdvisoryClassification } from "@octokit/graphql-schema/schema";

const BASE_URL = "https://prajeetguha.github.io/github-advisory-database-rss";
const ecosystemBase = (ecosystem: SecurityAdvisoryEcosystem) => {
    const low = ecosystem.toLowerCase();
    return {
        ecosystem: ecosystem,
        link: `${BASE_URL}/${low}.json`,
        homepage: `https://github.com/advisories?query=type%3Areviewed+ecosystem%3A${low}`
    };
};
const classificationBase = (classification: SecurityAdvisoryClassification) => {
    const low = classification.toLowerCase();
    return {
        classification: classification,
        link: `${BASE_URL}/${low}.json`,
        homepage: `https://github.com/advisories?query=type%3A${low}`
    };
};
export type ECOSYSTEM_FEED = { title: string; ecosystem: SecurityAdvisoryEcosystem; link: string; homepage: string };
export type CLASSIFICATION_FEED = { title: string; classification: SecurityAdvisoryClassification; link: string; homepage: string };
export const ECOSYSTEM_FEEDS: ECOSYSTEM_FEED[] = [
    {
        title: "Security Advisory for Java artifacts hosted at the Maven central repository",
        ...ecosystemBase("MAVEN")
    },
    {
        title: "Security Advisory for JavaScript packages hosted at npmjs.com",
        ...ecosystemBase("NPM")
    },
    {
        title: "Security Advisory for .NET packages hosted at the NuGet Gallery",
        ...ecosystemBase("NUGET")
    },
    {
        title: "Security Advisory for Python packages hosted at PyPI.org",
        ...ecosystemBase("PIP")
    }
];
export const CLASSIFICATION_FEEDS: CLASSIFICATION_FEED[] = [
    {
        title: "Collection of Malware Advisories",
        ...classificationBase("MALWARE")
    }
];
