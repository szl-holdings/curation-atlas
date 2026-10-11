import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Curation Atlas — GitHub policy intelligence",
  description: "Map repository policy drift, trace agent-change signals, compare curation methods, and inspect every score's evidence.",
  icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body className="antialiased">{children}</body></html>;
}
