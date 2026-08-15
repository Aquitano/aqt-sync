// The strings the document head and the generated OG card have to agree on. Both
// read them from here, so a reworded tagline cannot end up saying one thing in a
// link preview and another in search results.

// The origin every doc, installer, and share link actually points at. It is what
// metadataBase resolves relative URLs against, so getting it wrong publishes
// canonical and og:image URLs on a host that serves nothing.
export const siteOrigin = "https://web.sync.aquitano.me";

export const siteName = "aqt";

export const siteTitle = "aqt | Zero-knowledge encrypted sync";

export const siteDescription =
  "End-to-end encrypted file and folder sync. The server stores only ciphertext and opaque metadata.";

export const ogTitle = "aqt | Every file. Only yours.";

export const ogDescription =
  "Zero-knowledge sync for files, folders, Git remotes, snapshots, and private links.";
