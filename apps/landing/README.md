# Landing Page

## Overview
High-performance marketing landing page for Agenda Bella. Built with Next.js 14+ optimized for SEO, Core Web Vitals, and conversion optimization.

## Technology Stack
- **Framework**: Next.js 14+ with App Router
- **Rendering**: Static Site Generation (SSG) with Incremental Static Regeneration (ISR)
- **Styling**: Tailwind CSS with performance-optimized components
- **Analytics**: Google Analytics and custom conversion tracking
- **SEO**: Advanced meta tags, structured data, and sitemap generation

## Features
- Landing page with hero section
- Service showcase and benefits
- Clinic directory preview
- Customer testimonials and reviews
- SEO-optimized content pages
- Contact forms and lead capture
- Newsletter subscription
- Multi-language support (PT-BR primary)
- Progressive Web App (PWA) capabilities
- Advanced performance optimization

## Performance Targets
- **Core Web Vitals**: LCP < 2.5s, FID < 100ms, CLS < 0.1
- **Lighthouse Score**: 95+ for all metrics
- **SEO Score**: 100/100
- **Bundle Size**: < 100KB initial load

## Target Users
- Potential customers discovering the platform
- Clinic owners interested in joining
- SEO traffic from beauty and aesthetic searches
- Social media and advertising traffic

## Development
```bash
# Install dependencies
pnpm install

# Start development server
pnpm dev

# Build for production
pnpm build

# Analyze bundle size
pnpm analyze

# Generate sitemap
pnpm sitemap
```

## Environment Variables
- `NEXT_PUBLIC_SITE_URL`: Site URL for sitemap and SEO
- `NEXT_PUBLIC_GA_ID`: Google Analytics tracking ID
- `NEXT_PUBLIC_GTM_ID`: Google Tag Manager ID
- `NEXT_PUBLIC_API_URL`: API endpoint for contact forms