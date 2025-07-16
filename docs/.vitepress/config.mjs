import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'CWE Go Library',
  description: 'A comprehensive Go library for working with CWE (Common Weakness Enumeration) data',
  base: '/cwe/',


  
  themeConfig: {
    logo: '/cwe/logo.svg',

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
      ],
      '/zh/api/': [
        {
          text: 'API 参考',
          items: [
            { text: '概述', link: '/zh/api/' },
            { text: '核心类型', link: '/zh/api/core-types' },
            { text: 'API 客户端', link: '/zh/api/api-client' },
            { text: '数据获取器', link: '/zh/api/data-fetcher' },
            { text: '注册表', link: '/zh/api/registry' },
            { text: 'HTTP 客户端', link: '/zh/api/http-client' },
            { text: '速率限制器', link: '/zh/api/rate-limiter' },
            { text: '搜索和工具', link: '/zh/api/search-utils' },
            { text: '树操作', link: '/zh/api/tree' }
          ]
        }
      ],
      '/zh/examples/': [
        {
          text: '示例',
          items: [
            { text: '概述', link: '/zh/examples/' },
            { text: '基本用法', link: '/zh/examples/basic-usage' },
            { text: '获取 CWE 数据', link: '/zh/examples/fetch-cwe' },
            { text: '构建树', link: '/zh/examples/build-tree' },
            { text: '搜索和过滤', link: '/zh/examples/search-filter' },
            { text: '导出和导入', link: '/zh/examples/export-import' },
            { text: '速率限制客户端', link: '/zh/examples/rate-limited' }
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

  locales: {
    root: {
      label: 'English',
      lang: 'en',
      title: 'CWE Go Library',
      description: 'A comprehensive Go library for working with CWE (Common Weakness Enumeration) data',
      themeConfig: {
        nav: [
          { text: 'Home', link: '/' },
          { text: 'API Reference', link: '/api/' },
          { text: 'Examples', link: '/examples/' },
          { text: 'GitHub', link: 'https://github.com/scagogogo/cwe' }
        ]
      }
    },
    zh: {
      label: '简体中文',
      lang: 'zh-CN',
      title: 'CWE Go 库',
      description: '一个用于处理CWE（通用弱点枚举）数据的综合Go语言库',
      themeConfig: {
        nav: [
          { text: '首页', link: '/zh/' },
          { text: 'API 参考', link: '/zh/api/' },
          { text: '示例', link: '/zh/examples/' },
          { text: 'GitHub', link: 'https://github.com/scagogogo/cwe' }
        ],
        footer: {
          message: '基于 MIT 许可证发布。',
          copyright: '版权所有 © 2024 CWE Go Library'
        }
      }
    }
  },

  head: [
    ['link', { rel: 'icon', href: '/cwe/favicon.ico' }]
  ],

  markdown: {
    lineNumbers: true
  }
})
