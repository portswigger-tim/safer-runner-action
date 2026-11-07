/**
 * The job summary, as a pure pipeline: logs/ parse the raw logs, aggregate/ turns flow records
 * into summaries, render/ writes the Markdown. Every name or path a step chose goes through
 * redact.ts before it is printed (the C5 disclosure boundary). suggest.ts runs proxy/suggest.py
 * for the suggested http-filter.
 */

export * from './logs/dns-log';
export * from './logs/firewall-log';
export * from './logs/sudo-log';
export * from './aggregate/flows';
export * from './aggregate/containers';
export * from './aggregate/http-filter';
export * from './render/markdown';
export * from './render/report';
export * from './redact';
export * from './suggest';
