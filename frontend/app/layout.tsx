import "./globals.css";

export const metadata = {
  title: "DP Hellas Check My Link",
  description: "Έλεγχος ασφάλειας και κινδύνου για links.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="el"><body>{children}</body></html>;
}
