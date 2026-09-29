/**
 * A model addition for js/untrusted-data-to-external-api-more-sources.
 *
 * That query's own Sanitizer extension point has zero implementations in the shipped javascript-all library, and empirical testing against this repo's real code (array .filter() through a genuine TypeScript type guard, extracting only primitive numeric fields into a brand-new object, a structuredClone-style JSON round trip) confirmed none of them clear its taint: every value ever touched by remotely-fetched data stays tainted for this query no matter what validates or transforms it, because Sanitizer is empty by design. The query's own documentation names extending its safe-API classes, not sanitizing application code, as the supported way to reduce its noise, so that is what this file does - narrowly, for exactly the two packages this codebase's fetch-into-React-hook pattern hits.
 *
 * React's state and effect hooks, and react-router's navigation hook, are not external system boundaries the way a shell, a filesystem or a raw network client are: fetch() is the actual external call in this codebase's flow, and it is already covered as a source everywhere else this query and its siblings run. Nothing else is marked safe here, so a real external API - a database driver, a shell command, a different HTTP client, an eval - is still caught exactly as before.
 */

import javascript
import semmle.javascript.security.dataflow.ExternalAPIUsedWithUntrustedDataCustomizations

private class SafeReactPackage extends ExternalApiUsedWithUntrustedData::SafeExternalApiPackage {
  SafeReactPackage() { this = ["react", "react-router-dom"] }
}
