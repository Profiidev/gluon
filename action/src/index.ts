import { run } from './run';

// Run never rejects: errors are routed to core.setFailed / core.warning.
// oxlint-disable-next-line no-void
void run();
