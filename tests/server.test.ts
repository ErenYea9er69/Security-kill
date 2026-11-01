import { describe, it } from 'node:test';
import assert from 'node:assert';
import { generateAuditPromptContent } from '../src/prompts.js';
import { createServer } from '../src/server.js';

describe('MCP Server & Prompts Suite', () => {
  it('should generate comprehensive /security-audit prompt instructions', () => {
    const promptData = generateAuditPromptContent({
      target_path: './src-app',
      mode: 'quick',
      compliance: true,
      diff: false,
    });

    assert.ok(promptData.messages.length > 0);
    const text = promptData.messages[0].content.text;
    assert.match(text, /Security Audit/);
    assert.match(text, /\*\*Target Path:\*\* \.\/src-app/);
    assert.match(text, /\*\*Mode:\*\* quick/);
    assert.match(text, /Truth Rules/i);
    assert.match(text, /Untrusted Repository Rule/i);
    assert.match(text, /Phase 0: Recon and Section Map/i);
    assert.match(text, /\*\*Compliance Mapping:\*\* Enabled/);
    assert.match(text, /Master Skill Specification/);
    assert.match(text, /## What an attacker does, and what you do about it/);
  });

  it('should instantiate McpServer with registered tools, prompts, and resources', () => {
    const server = createServer();
    assert.ok(server);
    // Verify server has internal registrations
    const registeredTools = (server as any)._registeredTools;
    assert.ok(registeredTools['security_audit_preflight']);
    assert.ok(registeredTools['security_audit_section_map']);
    assert.ok(registeredTools['security_audit_scan_secrets']);
    assert.ok(registeredTools['security_audit_sast']);
    assert.ok(registeredTools['security_audit_scan_deps']);
    assert.ok(registeredTools['security_audit_generate_report']);
    assert.ok(registeredTools['security_audit_get_reference']);

    const registeredPrompts = (server as any)._registeredPrompts;
    assert.ok(registeredPrompts['security-audit']);
  });
});
