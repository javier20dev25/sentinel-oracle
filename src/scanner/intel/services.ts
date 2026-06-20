import type { PRFile } from '../rules'
import type { ServiceIntel, IntelRisk } from './types'

const KNOWN_SDKS: Record<string, string> = {
  'openai': 'OpenAI',
  '@anthropic-ai/sdk': 'Anthropic',
  'anthropic': 'Anthropic',
  'posthog-js': 'PostHog',
  'posthog-node': 'PostHog',
  'stripe': 'Stripe',
  '@stripe/react-stripe-js': 'Stripe',
  'sentry': 'Sentry',
  '@sentry/node': 'Sentry',
  '@sentry/react': 'Sentry',
  '@sentry/nextjs': 'Sentry',
  'mixpanel': 'Mixpanel',
  'segment': 'Segment',
  'analytics-node': 'Segment',
  'datadog-metrics': 'Datadog',
  '@datadog/browser-logs': 'Datadog',
  '@datadog/browser-rum': 'Datadog',
  'newrelic': 'New Relic',
  '@newrelic/next': 'New Relic',
  'twilio': 'Twilio',
  '@sendgrid/mail': 'SendGrid',
  'resend': 'Resend',
  'discord.js': 'Discord',
  '@slack/web-api': 'Slack',
  '@slack/bolt': 'Slack',
  'firebase': 'Firebase',
  'firebase-admin': 'Firebase',
  '@aws-sdk/client-s3': 'AWS S3',
  '@aws-sdk/client-lambda': 'AWS Lambda',
  '@aws-sdk/client-dynamodb': 'AWS DynamoDB',
  'aws-sdk': 'AWS SDK',
  '@google-cloud/storage': 'Google Cloud Storage',
  '@google-cloud/pubsub': 'Google Cloud Pub/Sub',
  '@azure/storage-blob': 'Azure Blob',
  '@azure/identity': 'Azure Identity',
  'redis': 'Redis',
  'ioredis': 'Redis',
  'mongoose': 'MongoDB',
  'mongodb': 'MongoDB',
  'pg': 'PostgreSQL',
  '@prisma/client': 'Prisma',
  'prisma': 'Prisma',
  'drizzle-orm': 'Drizzle ORM',
  'graphql': 'GraphQL',
  '@apollo/client': 'Apollo',
  'apollo-server': 'Apollo Server',
  'next-auth': 'NextAuth',
  'passport': 'Passport',
  'jsonwebtoken': 'JWT',
  'bcrypt': 'bcrypt',
  'argon2': 'Argon2',
}

const IMPORT_PATTERNS = [
  /(?:import|require)\s*\(?\s*['"`]([^'"`]+)['"`]/g,
  /from\s+['"`]([^'"`]+)['"`]/g,
]

export function analyzeServices(files: PRFile[]): ServiceIntel | undefined {
  const added: ServiceIntel['added'] = []
  const seen = new Set<string>()

  for (const file of files) {
    const patch = file.patch || ''
    const lines = patch.split('\n')
    let lineNum = 0
    for (const line of lines) {
      lineNum++
      if (!line.startsWith('+')) continue
      const content = line.slice(1)

      for (const pattern of IMPORT_PATTERNS) {
        pattern.lastIndex = 0
        let match
        while ((match = pattern.exec(content)) !== null) {
          const pkg = match[1]
          // Get the base package name (handle scoped packages)
          const basePkg = pkg.startsWith('@')
            ? '@' + pkg.split('/').slice(0, 2).join('/')
            : pkg.split('/')[0]

          if (KNOWN_SDKS[basePkg] && !seen.has(basePkg)) {
            seen.add(basePkg)
            added.push({ name: KNOWN_SDKS[basePkg], package: basePkg, file: file.filename, line: lineNum })
          } else if (KNOWN_SDKS[pkg] && !seen.has(pkg)) {
            seen.add(pkg)
            added.push({ name: KNOWN_SDKS[pkg], package: pkg, file: file.filename, line: lineNum })
          }
        }
      }
    }
  }

  if (added.length === 0) return undefined

  let risk: IntelRisk = 'low'
  const highRiskService = added.some(s =>
    /openai|anthropic|stripe/i.test(s.name) || /aws|gcp|azure/i.test(s.name)
  )
  if (highRiskService) risk = 'medium'

  return {
    summary: `${added.length} new ${added.length > 1 ? 'services' : 'service'} detected`,
    added, removed: [], risk,
  }
}
