// RSS 2.0 feed for the blog, generated from the single source of truth in
// $lib/blog/posts.js. Google had discovered /rss.xml (linked from the blog
// index) but the route never existed, so it 404'd; this makes it resolve.
import { posts } from '$lib/blog/posts.js';

const SITE = 'https://vindicara.io';

/**
 * Escape the five XML-significant characters for safe inclusion in text nodes.
 * @param {unknown} value
 */
function xml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * RFC 822 date (RSS pubDate) from an ISO YYYY-MM-DD, anchored at UTC midnight.
 * @param {string} iso
 */
function rfc822(iso) {
  return new Date(`${iso}T00:00:00Z`).toUTCString();
}

/** @type {import('./$types').RequestHandler} */
export function GET() {
  const items = posts
    .map((p) => {
      const url = `${SITE}${p.href}`;
      return `    <item>
      <title>${xml(p.title)}</title>
      <link>${xml(url)}</link>
      <guid isPermaLink="true">${xml(url)}</guid>
      <category>${xml(p.tag)}</category>
      <pubDate>${rfc822(p.date)}</pubDate>
      <description>${xml(p.description)}</description>
    </item>`;
    })
    .join('\n');

  const lastBuild = posts.length ? rfc822(posts[0].date) : new Date(0).toUTCString();

  const body = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>Vindicara Blog</title>
    <link>${SITE}/blog</link>
    <atom:link href="${SITE}/rss.xml" rel="self" type="application/rss+xml" />
    <description>Engineering, compliance, and strategy from the team building Project AIR.</description>
    <language>en-us</language>
    <lastBuildDate>${lastBuild}</lastBuildDate>
${items}
  </channel>
</rss>
`;

  return new Response(body, {
    headers: {
      'Content-Type': 'application/rss+xml; charset=utf-8',
      'Cache-Control': 'max-age=0, s-maxage=3600'
    }
  });
}
