import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
    title: "W9 Database Manager",
    description: "Centralized Data Management",
};

export default function RootLayout({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) {
    return (
        <html lang="en">
            <body>
                <div className="app">
                    {children}
                </div>
            </body>
        </html>
    );
}
