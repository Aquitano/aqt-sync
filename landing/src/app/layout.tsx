import type { Metadata, Viewport } from "next";
import "@fontsource-variable/space-grotesk";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/600.css";
import "@fontsource/pixelify-sans/600.css";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://aqt.sh"),
  title: "aqt | Zero-knowledge encrypted sync",
  description:
    "End-to-end encrypted file and folder sync. The server stores only ciphertext and opaque metadata.",
  openGraph: {
    title: "aqt | Every file. Only yours.",
    description:
      "Zero-knowledge sync for files, folders, Git remotes, snapshots, and private links.",
    type: "website",
  },
};

export const viewport: Viewport = {
  themeColor: "#f3dea3",
  colorScheme: "light",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
