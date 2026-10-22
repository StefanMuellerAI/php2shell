"use strict";
/*
 * Passive analysis of one ordinary page visit (all redirect hops + final HTML).
 * Reads only what the server volunteers: response headers, cookie names, HTML markers.
 * Pure function, no I/O — so it can be tested with fixtures.
 */

const PHP_PLATFORMS = new Set([
  "WordPress", "WooCommerce", "TYPO3", "Joomla", "Drupal", "Contao", "Shopware", "Magento",
  "PrestaShop", "JTL-Shop", "Gambio", "OXID eShop", "Nextcloud", "Roundcube", "phpMyAdmin",
  "MediaWiki", "Moodle", "ILIAS", "Kirby", "Craft CMS", "Laravel", "REDAXO", "Neos", "Pimcore",
  "Concrete CMS", "ProcessWire", "Grav", "Joomla!", "Matomo",
]);

// order = which platform is shown as "the" system when several match
const PRIORITY = [
  "Magento", "Shopware", "WooCommerce", "PrestaShop", "JTL-Shop", "Gambio", "OXID eShop",
  "WordPress", "TYPO3", "Joomla", "Drupal", "Contao", "Nextcloud", "Roundcube", "phpMyAdmin",
  "MediaWiki", "Moodle", "ILIAS", "Kirby", "Craft CMS", "REDAXO", "Neos", "Pimcore",
  "Concrete CMS", "ProcessWire", "Grav", "Laravel",
];

// generator meta → platform
const GENERATORS = [
  [/^wordpress\s*([\d.]+)?/i, "WordPress"],
  [/^woocommerce\s*([\d.]+)?/i, "WooCommerce"],
  [/^typo3\b/i, "TYPO3"],
  [/^joomla/i, "Joomla"],
  [/^drupal\s*([\d.]+)?/i, "Drupal"],
  [/^contao\b/i, "Contao"],
  [/^shopware\b/i, "Shopware"],
  [/^prestashop\b/i, "PrestaShop"],
  [/^jtl-shop\b/i, "JTL-Shop"],
  [/^gambio\b/i, "Gambio"],
  [/^oxid\b/i, "OXID eShop"],
  [/^mediawiki\s*([\d.]+)?/i, "MediaWiki"],
  [/^moodle\b/i, "Moodle"],
  [/^kirby\b/i, "Kirby"],
  [/^redaxo\b/i, "REDAXO"],
  [/^neos\b/i, "Neos"],
  [/^concrete/i, "Concrete CMS"],
  [/^processwire\b/i, "ProcessWire"],
  [/^grav\b/i, "Grav"],
  [/^webflow\b/i, "SAAS:Webflow"],
  [/^wix\.com/i, "SAAS:Wix"],
  [/^squarespace\b/i, "SAAS:Squarespace"],
  [/^jimdo\b/i, "SAAS:Jimdo"],
  [/^framer\b/i, "SAAS:Framer"],
  [/^hubspot\b/i, "SAAS:HubSpot"],
  [/^google sites\b/i, "SAAS:Google Sites"],
];

// HTML markers → platform
const BODY_MARKERS = [
  [/\/wp-content\/|\/wp-includes\//i, "WordPress", "WordPress-Pfade im Seitenquelltext"],
  [/\/plugins\/woocommerce\/|woocommerce-no-js|class="[^"]*\bwoocommerce\b/i, "WooCommerce", "WooCommerce-Bausteine im Seitenquelltext"],
  [/typo3temp\/|typo3conf\/|\/typo3\/sysext\/|_assets\/[0-9a-f]{32}\//i, "TYPO3", "TYPO3-Pfade im Seitenquelltext"],
  [/\/media\/system\/js\/|\/media\/jui\/|\/media\/templates\/site\//i, "Joomla", "Joomla-Pfade im Seitenquelltext"],
  [/drupal-settings-json|\/sites\/default\/files\/|Drupal\.settings/i, "Drupal", "Drupal-Bausteine im Seitenquelltext"],
  [/\/bundles\/contaocore\/|\/assets\/contao\//i, "Contao", "Contao-Pfade im Seitenquelltext"],
  [/\/bundles\/storefront\//i, "Shopware", "Shopware-Pfade im Seitenquelltext"],
  [/Magento_[A-Z]|mage\/cookies|"Magento_Ui\//, "Magento", "Magento-Bausteine im Seitenquelltext"],
  [/data-requesttoken=|oc_requesttoken/i, "Nextcloud", "Nextcloud-Bausteine im Seitenquelltext"],
  [/rcmail\.set_env|<title>[^<]*roundcube/i, "Roundcube", "Roundcube-Bausteine im Seitenquelltext"],
  [/<title>[^<]*phpmyadmin/i, "phpMyAdmin", "phpMyAdmin-Oberfläche"],
  [/static\.wixstatic\.com|wix-bolt|_wixCssImports/i, "SAAS:Wix", "Wix-Bausteine im Seitenquelltext"],
  [/static1\.squarespace\.com|squarespace-cdn/i, "SAAS:Squarespace", "Squarespace-Bausteine im Seitenquelltext"],
  [/cdn\.shopify\.com|Shopify\.theme/i, "SAAS:Shopify", "Shopify-Bausteine im Seitenquelltext"],
  [/data-wf-site=|data-wf-page=/i, "SAAS:Webflow", "Webflow-Bausteine im Seitenquelltext"],
  [/jimcdn\.com|jimstatic\.com|jimdo-storage/i, "SAAS:Jimdo", "Jimdo-Bausteine im Seitenquelltext"],
  [/framerusercontent\.com/i, "SAAS:Framer", "Framer-Bausteine im Seitenquelltext"],
];

// cookie name → platform (or plain PHP)
const COOKIES = [
  [/^PHPSESSID$/i, null, "PHP-Sitzungscookie (PHPSESSID)"],
  [/^(wordpress_|wp-settings|wp_lang|wordpress_test_cookie)/i, "WordPress", "WordPress-Cookie"],
  [/^woocommerce_/i, "WooCommerce", "WooCommerce-Cookie"],
  [/^(fe_typo_user|be_typo_user)$/i, "TYPO3", "TYPO3-Cookie"],
  [/^S?SESS[0-9a-f]{32}$/i, "Drupal", "Drupal-Sitzungscookie"],
  [/^(csrf_contao|contao_)/i, "Contao", "Contao-Cookie"],
  [/^(sw-states|sw-context-token|session-\d+)$/i, "Shopware", "Shopware-Cookie"],
  [/^(mage-cache-sessid|mage-messages|form_key)$/i, "Magento", "Magento-Cookie"],
  [/^PrestaShop-/i, "PrestaShop", "PrestaShop-Cookie"],
  [/^JTLSHOP$/i, "JTL-Shop", "JTL-Shop-Cookie"],
  [/^GXsid/i, "Gambio", "Gambio-Cookie"],
  [/^(oc_sessionPassphrase|nc_sameSiteCookie)/i, "Nextcloud", "Nextcloud-Cookie"],
  [/^roundcube_/i, "Roundcube", "Roundcube-Cookie"],
  [/^MoodleSession/i, "Moodle", "Moodle-Cookie"],
  [/^kirby_session$/i, "Kirby", "Kirby-Cookie"],
  [/^CraftSessionId$/i, "Craft CMS", "Craft-Cookie"],
  [/^laravel_session$/i, "Laravel", "Laravel-Cookie"],
];

function str(v) {
  if (v == null) return "";
  return Array.isArray(v) ? v.join(", ") : String(v);
}
function cookieNames(setCookie) {
  const list = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
  return list.map((c) => String(c).split("=")[0].trim()).filter(Boolean);
}
function generatorTags(html) {
  const out = [];
  const re = /<meta\b[^>]*>/gi;
  let m;
  while ((m = re.exec(html)) && out.length < 10) {
    const tag = m[0];
    if (!/name\s*=\s*["']?generator["']?/i.test(tag)) continue;
    const c = tag.match(/content\s*=\s*"([^"]*)"|content\s*=\s*'([^']*)'/i);
    if (c) out.push((c[1] || c[2] || "").trim().slice(0, 120));
  }
  return out;
}

function adminLink(platform, finalUrl, wpBase) {
  let origin;
  try {
    const f = new URL(finalUrl);
    if (f.protocol !== "http:" && f.protocol !== "https:") return null;
    origin = f.origin;
  } catch { return null; }
  // wpBase comes from the checked site's Link header: only accept it on the same origin
  let base = origin + "/";
  if (wpBase) {
    try {
      const b = new URL(wpBase, finalUrl);
      if (b.origin === origin) base = b.origin + b.pathname.replace(/[^/]*$/, "");
    } catch { /* ignore */ }
  }
  switch (platform) {
    case "WordPress":
    case "WooCommerce":
      return { url: base + "wp-admin/site-health.php?tab=debug", label: "WordPress: Website-Zustand öffnen", where: "Bereich „Server“ aufklappen, Zeile „PHP-Version“ (nur für Administratoren sichtbar)", fallback: "Lädt die Seite nicht, melden Sie sich unter /wp-admin an und öffnen Werkzeuge → Website-Zustand → Bericht." };
    case "Joomla":
      return { url: origin + "/administrator/index.php?option=com_admin&view=sysinfo", label: "Joomla: Systeminformationen öffnen", where: "Zeile „PHP-Version“ (nur für Super User)" };
    case "Drupal":
      return { url: origin + "/admin/reports/status", label: "Drupal: Statusbericht öffnen", where: "Zeile „PHP“ (nur für Administratoren)" };
    case "TYPO3":
      return { url: origin + "/typo3/", label: "TYPO3-Backend öffnen", where: "oben rechts das Info-Symbol „System-Information“, Zeile „PHP-Version“ (nur für Administratoren)", fallback: "Liegt Ihr Backend unter einer anderen Adresse als /typo3/, melden Sie sich dort an." };
    default:
      return null;
  }
}

const SYSTEM_KEY = {
  WordPress: "wordpress", WooCommerce: "shop", TYPO3: "typo3", Joomla: "joomla", Drupal: "drupal",
  Magento: "shop", Shopware: "shop", PrestaShop: "shop", "JTL-Shop": "shop", Gambio: "shop", "OXID eShop": "shop",
};

/**
 * @param {{url:string,status:number,headers:Object,body?:string}[]} hops
 */
function analyze(hops) {
  const evidence = new Set();
  const platforms = new Map();
  const saasHits = new Map();
  let version = null, versionSource = null, phpYes = false, wpBase = null;

  const addPlatform = (name, ver, why) => {
    if (name.startsWith("SAAS:")) { saasHits.set(name.slice(5), true); if (why) evidence.add(why); return; }
    if (name === "Joomla!") name = "Joomla";
    const prev = platforms.get(name);
    if (!prev) platforms.set(name, { version: ver || null });
    else if (ver && !prev.version) prev.version = ver;
    if (why) evidence.add(why);
  };

  for (const h of hops) {
    const H = h.headers || {};
    const xpb = str(H["x-powered-by"]);
    const server = str(H["server"]);

    for (const [src, val] of [["X-Powered-By", xpb], ["Server", server]]) {
      const m = val.match(/PHP\/(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?[^\s,;)]*)/i);
      if (m && !version) { version = m[1]; versionSource = src; }
    }
    if (/\bphp\b/i.test(xpb)) { phpYes = true; evidence.add("Header X-Powered-By: " + xpb.slice(0, 80)); }
    else if (/php\//i.test(server)) { phpYes = true; evidence.add("Header Server: " + server.slice(0, 80)); }

    const link = str(H["link"]);
    const wp = link.match(/<([^>]+?)wp-json\/?>\s*;\s*rel="?https:\/\/api\.w\.org/i);
    if (wp) { addPlatform("WordPress", null, "WordPress-Schnittstelle im Header (wp-json)"); if (!wpBase) wpBase = wp[1]; }
    if (H["x-pingback"]) addPlatform("WordPress", null, "WordPress-Header X-Pingback");
    if (/wordpress/i.test(str(H["x-redirect-by"]))) addPlatform("WordPress", null, "WordPress-Weiterleitung (X-Redirect-By)");
    const xgen = str(H["x-generator"]);
    if (xgen) {
      for (const [re, name] of GENERATORS) {
        const m = xgen.match(re);
        if (m) { addPlatform(name, m[1], "Header X-Generator: " + xgen.slice(0, 60)); break; }
      }
    }
    if (H["x-drupal-cache"] || H["x-drupal-dynamic-cache"]) addPlatform("Drupal", null, "Drupal-Cache-Header");

    // SaaS fingerprints in headers
    if (/pepyaka/i.test(server) || H["x-wix-request-id"]) addPlatform("SAAS:Wix", null, "Wix-Server");
    if (/squarespace/i.test(server)) addPlatform("SAAS:Squarespace", null, "Squarespace-Server");
    if (H["x-shopid"] || H["x-shopify-stage"] || /shopify/i.test(xpb)) addPlatform("SAAS:Shopify", null, "Shopify-Server");
    if (/^framer/i.test(server)) addPlatform("SAAS:Framer", null, "Framer-Server");
    if (/^vercel/i.test(server) || H["x-vercel-id"]) addPlatform("SAAS:Vercel", null, "Gehostet bei Vercel");
    if (/^netlify/i.test(server) || H["x-nf-request-id"]) addPlatform("SAAS:Netlify", null, "Gehostet bei Netlify");
    if (/^github\.com/i.test(server)) addPlatform("SAAS:GitHub Pages", null, "Gehostet bei GitHub Pages");
    if (Object.keys(H).some((k) => k.startsWith("x-hs-"))) addPlatform("SAAS:HubSpot", null, "HubSpot-Server");

    for (const name of cookieNames(H["set-cookie"])) {
      for (const [re, plat, why] of COOKIES) {
        if (re.test(name)) { if (plat) addPlatform(plat, null, why); else { phpYes = true; evidence.add(why); } break; }
      }
    }

    try {
      if (/\.php(\?|$)/i.test(new URL(h.url).pathname)) { phpYes = true; evidence.add("Adresse endet auf .php"); }
    } catch { /* ignore */ }
  }

  const last = hops[hops.length - 1] || { url: "", status: 0, headers: {}, body: "" };
  const html = typeof last.body === "string" ? last.body : "";
  for (const g of generatorTags(html)) {
    for (const [re, name] of GENERATORS) {
      const m = g.match(re);
      if (m) { addPlatform(name, m[1], "Generator-Angabe: " + g); break; }
    }
  }
  for (const [re, name, why] of BODY_MARKERS) if (re.test(html)) addPlatform(name, null, why);

  // pick primary platform
  const names = [...platforms.keys()];
  let primary = PRIORITY.find((p) => platforms.has(p)) || names[0] || null;
  let display = primary;
  if (primary === "WooCommerce" && platforms.has("WordPress")) display = "WordPress mit WooCommerce";
  const platformVersion = !primary ? null
    : (primary === "WooCommerce" && platforms.has("WordPress")) ? platforms.get("WordPress").version
    : platforms.get(primary).version;

  if (version) phpYes = true;
  if (names.some((n) => PHP_PLATFORMS.has(n))) phpYes = true;

  const saas = phpYes ? null : ([...saasHits.keys()][0] || null);

  // bot protection / blocked
  const H = last.headers || {};
  const st = last.status || 0;
  const blocked = (st === 403 || st === 429 || st === 503) &&
    (Boolean(H["cf-mitigated"]) || (/cloudflare/i.test(str(H["server"])) && /challenge|cf-chl|just a moment/i.test(html)) || /captcha|access denied|zugriff verweigert/i.test(html));

  return {
    finalUrl: last.url,
    status: st,
    hops: hops.length,
    php: {
      detected: phpYes ? "yes" : "unknown",
      version,
      versionSource,
    },
    platform: primary ? {
      name: display,
      key: SYSTEM_KEY[primary] || (PHP_PLATFORMS.has(primary) ? "custom" : null),
      version: platformVersion,
      admin: adminLink(primary, last.url, wpBase),
    } : null,
    saas,
    blocked,
    evidence: [...evidence].slice(0, 8),
  };
}

module.exports = { analyze };
