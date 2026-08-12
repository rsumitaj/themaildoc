/**
 * Naming the service behind a sending IP, using only what is already in the
 * report.
 *
 * Every guess here comes from the authenticated domains the reporter recorded
 * — an `amazonses.com` SPF domain or a `mcdlv.net` DKIM signature identifies
 * the platform without a single lookup, a geo database or a licence fee. It is
 * labelled as inferred wherever it is shown, because a DKIM selector is a
 * convention and not a promise.
 *
 * Ordered longest-suffix-first so `mail.protection.outlook.com` never matches
 * as plain Outlook.
 */

interface Signature {
  /** Matched against SPF and DKIM domains, as a suffix. */
  suffix: string;
  name: string;
}

const BY_DOMAIN: readonly Signature[] = [
  { suffix: 'mail.protection.outlook.com', name: 'Microsoft 365' },
  { suffix: 'protection.outlook.com', name: 'Microsoft 365' },
  { suffix: 'outlook.com', name: 'Microsoft 365' },
  { suffix: 'google.com', name: 'Google Workspace' },
  { suffix: 'gmail.com', name: 'Gmail' },
  { suffix: 'googlemail.com', name: 'Gmail' },
  { suffix: 'amazonses.com', name: 'Amazon SES' },
  { suffix: 'sendgrid.net', name: 'SendGrid' },
  { suffix: 'sendgrid.com', name: 'SendGrid' },
  { suffix: 'mailgun.org', name: 'Mailgun' },
  { suffix: 'mailgun.net', name: 'Mailgun' },
  { suffix: 'mcsv.net', name: 'Mailchimp' },
  { suffix: 'mcdlv.net', name: 'Mailchimp' },
  { suffix: 'mailchimpapp.net', name: 'Mailchimp' },
  { suffix: 'mandrillapp.com', name: 'Mandrill' },
  { suffix: 'postmarkapp.com', name: 'Postmark' },
  { suffix: 'pm-bounces.net', name: 'Postmark' },
  { suffix: 'resend.com', name: 'Resend' },
  { suffix: 'sparkpostmail.com', name: 'SparkPost' },
  { suffix: 'klaviyomail.com', name: 'Klaviyo' },
  { suffix: 'hubspotemail.net', name: 'HubSpot' },
  { suffix: 'hubspot.com', name: 'HubSpot' },
  { suffix: 'zendesk.com', name: 'Zendesk' },
  { suffix: 'freshemail.io', name: 'Freshworks' },
  { suffix: 'intercom-mail.com', name: 'Intercom' },
  { suffix: 'intercomcdn.com', name: 'Intercom' },
  { suffix: 'sendinblue.com', name: 'Brevo' },
  { suffix: 'brevo.com', name: 'Brevo' },
  { suffix: 'mailjet.com', name: 'Mailjet' },
  { suffix: 'activehosted.com', name: 'ActiveCampaign' },
  { suffix: 'constantcontact.com', name: 'Constant Contact' },
  { suffix: 'ctctemail.com', name: 'Constant Contact' },
  { suffix: 'shopifyemail.com', name: 'Shopify Email' },
  { suffix: 'shopify.com', name: 'Shopify' },
  { suffix: 'stripe.com', name: 'Stripe' },
  { suffix: 'salesforce.com', name: 'Salesforce' },
  { suffix: 'exacttarget.com', name: 'Salesforce Marketing Cloud' },
  { suffix: 'zoho.com', name: 'Zoho Mail' },
  { suffix: 'zohomail.com', name: 'Zoho Mail' },
  { suffix: 'atlassian.net', name: 'Atlassian' },
  { suffix: 'notion.so', name: 'Notion' },
  { suffix: 'slack.com', name: 'Slack' },
  { suffix: 'github.com', name: 'GitHub' },
  { suffix: 'mimecast.com', name: 'Mimecast' },
  { suffix: 'pphosted.com', name: 'Proofpoint' },
  { suffix: 'ppe-hosted.com', name: 'Proofpoint' },
  { suffix: 'barracudanetworks.com', name: 'Barracuda' },
  { suffix: 'icloud.com', name: 'iCloud Mail' },
  { suffix: 'me.com', name: 'iCloud Mail' },
  { suffix: 'yahoodns.net', name: 'Yahoo' },
  { suffix: 'fastmail.com', name: 'Fastmail' },
  { suffix: 'messagingengine.com', name: 'Fastmail' },
];

/** Selectors distinctive enough to name a platform on their own. */
const BY_SELECTOR: Readonly<Record<string, string>> = {
  google: 'Google Workspace',
  selector1: 'Microsoft 365',
  selector2: 'Microsoft 365',
  mandrill: 'Mandrill',
  resend: 'Resend',
  amazonses: 'Amazon SES',
  zoho: 'Zoho Mail',
  zendesk1: 'Zendesk',
  zendesk2: 'Zendesk',
  mailjet: 'Mailjet',
  postmark: 'Postmark',
  klaviyo: 'Klaviyo',
  sendinblue: 'Brevo',
  brevo: 'Brevo',
  litesrv: 'Mailchimp',
  fm1: 'Fastmail',
  fm2: 'Fastmail',
  fm3: 'Fastmail',
};

const SORTED = [...BY_DOMAIN].sort((a, b) => b.suffix.length - a.suffix.length);

/**
 * The likely platform behind a set of authenticated domains and selectors, or
 * `null` when nothing here is confident enough to be worth saying.
 */
export function inferService(
  domains: readonly string[],
  selectors: readonly (string | null)[],
): string | null {
  for (const raw of domains) {
    const domain = raw.trim().toLowerCase();
    if (!domain) continue;
    for (const signature of SORTED) {
      if (domain === signature.suffix || domain.endsWith(`.${signature.suffix}`)) {
        return signature.name;
      }
    }
  }

  for (const selector of selectors) {
    const name = selector ? BY_SELECTOR[selector.trim().toLowerCase()] : undefined;
    if (name) return name;
  }

  return null;
}
