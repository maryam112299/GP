import type { Metadata } from 'next';
import { Outfit, JetBrains_Mono } from 'next/font/google';
import './globals.css';
import { Toaster } from 'react-hot-toast';

const outfit = Outfit({
  subsets: ['latin'],
  variable: '--font-outfit',
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'AI Agent Security Tester — MAESTRO & ATFAA Vulnerability Analysis',
  description:
    'Professional security and vulnerability testing platform for AI agents and MCP servers. ' +
    'Powered by MAESTRO framework layer decomposition and ATFAA behavioral threat analysis.',
  keywords: ['AI security', 'LLM vulnerabilities', 'MAESTRO', 'ATFAA', 'MCP security', 'prompt injection'],
  openGraph: {
    title: 'AI Agent Security Tester',
    description: 'Breaking AI: Vulnerability testing for LLM and MCP systems.',
    type: 'website',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${outfit.variable} ${jetbrainsMono.variable}`} suppressHydrationWarning>
      <body style={{ fontFamily: 'var(--font-outfit), system-ui, sans-serif' }} suppressHydrationWarning>
        {children}
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#ffffff',
              color: '#0f172a',
              border: '1px solid #e5e7eb',
              borderRadius: '10px',
              fontSize: '0.875rem',
              boxShadow: '0 4px 12px rgba(15,23,42,0.1)',
            },
            success: { iconTheme: { primary: '#16a34a', secondary: '#fff' } },
            error:   { iconTheme: { primary: '#dc2626', secondary: '#fff' } },
          }}
        />
      </body>
    </html>
  );
}
