import type { Metadata } from 'next';
import '../styles/globals.css';
export const metadata: Metadata = {
  title: 'ChainVanta · Cryptographic intelligence',
  description: 'Evidence-backed cryptographic inventory by SYNTRIASS',
};
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
