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
    <html lang="en" className={`${outfit.variable} ${jetbrainsMono.variable}`}>
      <body style={{ fontFamily: 'var(--font-outfit), system-ui, sans-serif' }}>
        {children}
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#161b24',
              color: '#f0f6fc',
              border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: '10px',
              fontSize: '0.875rem',
            },
            success: { iconTheme: { primary: '#06d6a0', secondary: '#fff' } },
            error:   { iconTheme: { primary: '#f85149', secondary: '#fff' } },
          }}
        />
      </body>
    </html>
  );
}
