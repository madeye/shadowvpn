import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'ShadowVPN',
  description:
    'A UDP-based, pre-shared-key, user-mode VPN written in Rust. shadowsocks AEAD wire format, cross-platform TUN, and user-mode policy routing (gfwlist / chinadns).',
  base: '/shadowvpn/',
  lastUpdated: true,
  cleanUrls: true,

  head: [
    ['meta', { property: 'og:title', content: 'ShadowVPN' }],
    [
      'meta',
      {
        property: 'og:description',
        content: 'A UDP-based, pre-shared-key, user-mode VPN written in Rust.',
      },
    ],
    ['meta', { property: 'og:type', content: 'website' }],
  ],

  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/what-is-shadowvpn', activeMatch: '/guide/' },
      { text: 'Reference', link: '/reference/configuration', activeMatch: '/reference/' },
      { text: 'Benchmarks', link: '/reference/benchmarks' },
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Introduction',
          items: [
            { text: 'What is ShadowVPN?', link: '/guide/what-is-shadowvpn' },
            { text: 'Quick start', link: '/guide/quick-start' },
            { text: 'Installation', link: '/guide/installation' },
          ],
        },
        {
          text: 'Usage',
          items: [
            { text: 'Configuration', link: '/guide/configuration' },
            { text: 'Running server & client', link: '/guide/running' },
            { text: 'Routing & IP forwarding', link: '/guide/routing' },
            { text: 'Policy routing (split tunnel)', link: '/guide/policy-routing' },
            { text: 'Multiple clients (NAT mode)', link: '/guide/multi-client' },
            { text: 'Running as a service', link: '/guide/service' },
          ],
        },
        {
          text: 'Tools & apps',
          items: [
            { text: 'Config URIs & QR codes', link: '/guide/uri-qr' },
            { text: 'Desktop app', link: '/guide/desktop' },
          ],
        },
        {
          text: 'Help',
          items: [{ text: 'Troubleshooting', link: '/guide/troubleshooting' }],
        },
      ],
      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'Configuration reference', link: '/reference/configuration' },
            { text: 'Wire protocol', link: '/reference/wire-protocol' },
            { text: 'Ciphers', link: '/reference/ciphers' },
            { text: 'Carrier obfuscation', link: '/reference/obfuscation' },
            { text: 'Architecture & project layout', link: '/reference/architecture' },
            { text: 'Benchmarks', link: '/reference/benchmarks' },
            { text: 'Testing (Docker e2e)', link: '/reference/testing' },
          ],
        },
      ],
    },

    socialLinks: [{ icon: 'github', link: 'https://github.com/madeye/shadowvpn' }],

    search: { provider: 'local' },

    editLink: {
      pattern: 'https://github.com/madeye/shadowvpn/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'ShadowVPN — a UDP PSK user-mode VPN in Rust',
    },

    outline: { level: [2, 3] },
  },
})
