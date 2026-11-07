import { execSync } from 'child_process';
import readline from 'readline';

/**
 * SEC-21: Ultra-Hardened Database Maintenance Script
 * 
 * CRITICAL SAFETY RULES:
 * 1. Strictly blocks accidental or unauthorized execution against production.
 * 2. Requires verified SuperAdmin email authorization and explicit confirmation passphrase.
 * 3. Requires interactive multi-step confirmation before executing any delete command.
 */

const collectionsToPurge = [
  'employees',
  'onboarding_submissions',
  'draft_submissions',
  'correction_requests',
  'referral_invites',
  'staff_referral_invites',
  'leave_requests',
  'leaves',
  'account_updates',
  'resignations',
  'disciplinary_actions',
  'complaints',
  'reward_redemptions',
  'attendance',
  'user_engagement',
  'bgv_records',
  'leave_balances',
  'legacy_employee_imports',
  '_auth_attempts',
  'notifications'
];

// 1. Detect Active Firebase Project
let activeProject = '';
try {
  activeProject = execSync('npx firebase use', { encoding: 'utf8' }).trim();
} catch (err) {
  console.error('[SECURITY BLOCK] Unable to verify active Firebase project. Aborting.');
  process.exit(1);
}

const isProduction = activeProject.includes('hr-portal-unique-delta') || activeProject.includes('production');

// 2. SuperAdmin Authorization Gate
const authorizedSuperAdminEmail = process.env.AUTHORIZED_SUPERADMIN_EMAIL;
const requiredPassphrase = process.env.SUPERADMIN_PURGE_CONFIRMATION_PHRASE;

console.log('====================================================');
console.log('  UDF FIRESTORE DATABASE PURGE - AUTHORIZATION CHECK');
console.log('====================================================');
console.log(`Active Firebase Project: ${activeProject}`);

if (isProduction) {
  console.error('\n🚨 [DANGER: PRODUCTION ENVIRONMENT DETECTED]');
  console.error('Target Project:', activeProject);
  console.error('Automated or unauthenticated deletion of production data is strictly prohibited.');

  if (!authorizedSuperAdminEmail) {
    console.error('\n❌ [ACCESS DENIED] Missing AUTHORIZED_SUPERADMIN_EMAIL environment variable.');
    console.error('Only verified SuperAdmin can initiate database maintenance.');
    process.exit(1);
  }

  if (requiredPassphrase !== 'PURGE-UDF-DATA-SUPERADMIN-CONFIRMED') {
    console.error('\n❌ [ACCESS DENIED] Invalid or missing SUPERADMIN_PURGE_CONFIRMATION_PHRASE.');
    console.error('Execution blocked.');
    process.exit(1);
  }
}

// 3. Interactive Multi-Step Confirmation Prompt
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const askQuestion = (query) => new Promise((resolve) => rl.question(query, resolve));

async function runSafePurge() {
  console.log(`\nTarget Collections (${collectionsToPurge.length}):`);
  console.log(collectionsToPurge.join(', '));
  console.log('\n----------------------------------------------------');

  const confirmProject = await askQuestion(`Type the EXACT project name to confirm (${activeProject}): `);
  if (confirmProject.trim() !== activeProject.trim()) {
    console.log('Project name mismatch. Aborted safely.');
    rl.close();
    process.exit(0);
  }

  const confirmWord = await askQuestion('Type "I CONFIRM COMPLETE DATA DELETION" to proceed: ');
  if (confirmWord.trim() !== 'I CONFIRM COMPLETE DATA DELETION') {
    console.log('Confirmation phrase mismatch. Aborted safely.');
    rl.close();
    process.exit(0);
  }

  rl.close();

  console.log('\n=== Starting Verified SuperAdmin Purge ===');
  for (const col of collectionsToPurge) {
    console.log(`\n--> Purging collection: ${col}...`);
    try {
      execSync(`npx firebase firestore:delete -r -f ${col}`, {
        stdio: 'inherit',
        shell: true
      });
      console.log(`[SUCCESS] Purged ${col}`);
    } catch (err) {
      console.error(`[ERROR] Failed to purge ${col}:`, err.message);
    }
  }

  console.log('\n=== Purge Completed ===');
}

runSafePurge().catch((err) => {
  console.error('Fatal error during purge:', err);
  process.exit(1);
});
