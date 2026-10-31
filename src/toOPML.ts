
import xml from "xml";
import type {
    ECOSYSTEM_FEED,
    CLASSIFICATION_FEED
} from "./RSS_FEEDS.ts";

type RSS_FEED = ECOSYSTEM_FEED | CLASSIFICATION_FEED;

const convertItemToOutline = (item: RSS_FEED) => {
    return {
        outline: {
            _attr: {
                type: "rss",
                title: item.title,
                htmlUrl: item.homepage || item.link,
                xmlUrl: item.link
            }
        }
    };
};

export const convertJsonToOPML = (items: RSS_FEED[]) => {
    const head = {
        head: [
            {
                title: "GitHub Advisory Database Subscriptions"
            },
            {
                dateCreated: new Date().toISOString()
            }
        ]
    };

    return `<?xml version="1.0" encoding="UTF-8"?>
<opml version="2.0">
    ${xml(head, true)}
    ${xml(
        {
            body: [
                {
                    outline: [
                        {
                            _attr: {
                                title: "GitHub Advisory Database Feeds"
                            }
                        },
                        {
                            outline: items.map((item) =>
                                convertItemToOutline(item)
                            )
                        }
                    ]
                }
            ]
        },
        true
    )}
</opml>`;
};
