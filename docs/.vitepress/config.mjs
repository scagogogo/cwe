import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'CWE Go Library',
  description: 'A comprehensive Go library for working with CWE (Common Weakness Enumeration) data',
  base: '/cwe/',
  
  themeConfig: {
    logo: '/logo.svg',
    
    nav: [
      { text: 'Home', link: '/' },
      { text: 'API Reference', link: '/api/' },
      { text: 'Examples', link: '/examples/' },
      { text: 'GitHub', link: 'https://github.com/scagogogo/cwe' }
    ],

    sidebar: {
      '/api/': [
        {
          text: 'API Reference',
          items: [
            { text: 'Overview', link: '/api/' },
            { text: 'Core Types', link: '/api/core-types' },
            { text: 'API Client', link: '/api/api-client' },
            { text: 'Data Fetcher', link: '/api/data-fetcher' },
            { text: 'Registry', link: '/api/registry' },
            { text: 'HTTP Client', link: '/api/http-client' },
            { text: 'Rate Limiter', link: '/api/rate-limiter' },
            { text: 'Search & Utils', link: '/api/search-utils' },
            { text: 'Tree Operations', link: '/api/tree' }
          ]
        }
      ],
      '/examples/': [
        {
          text: 'Examples',
          items: [
            { text: 'Overview', link: '/examples/' },
            { text: 'Basic Usage', link: '/examples/basic-usage' },
            { text: 'Fetching CWE Data', link: '/examples/fetch-cwe' },
            { text: 'Building Trees', link: '/examples/build-tree' },
            { text: 'Search & Filter', link: '/examples/search-filter' },
            { text: 'Export & Import', link: '/examples/export-import' },
            { text: 'Rate Limited Client', link: '/examples/rate-limited' }
          ]
        }
      ]
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/scagogogo/cwe' }
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2024 CWE Go Library'
    },

    search: {
      provider: 'local'
    }
  },

  head: [
    ['link', { rel: 'icon', href: '/favicon.ico' }]
  ],

  markdown: {
    lineNumbers: true
  }
})
