import { describe, it } from 'node:test';
import assert from 'node:assert';
import { generateAuditPromptContent } from '../src/prompts.js';
import { createServer } from '../src/server.js';

describe('MCP Server & Tools Suite', () => {
  it('should generate comprehensive /security-audit prompt instructions', async () => {
    const promptData = await generateAuditPromptContent({
      target_path: './src-app',
      mode: 'quick',
      compliance: true,
      diff: false,
    });

    assert.ok(promptData.messages.length > 0);
    const text = promptData.messages[0].content.text;
    assert.match(text, /Security Audit Directive for \.\/src-app/);
    assert.match(text, /\*\*Mode:\*\* quick/);
    assert.match(text, /Truth Rules/i);
    assert.match(text, /UNTRUSTED/i);
    assert.match(text, /Active Specialist Teams/i);
  });

  it('should instantiate McpServer with all registered tools, prompts, and resources', () => {
    const server = createServer();
    assert.ok(server);
    // Verify server has internal tool registrations
    const registeredTools = (server as any)._registeredTools;
    assert.ok(registeredTools['security_audit_orchestrate'], 'security_audit_orchestrate must be registered');
    assert.ok(registeredTools['security_audit_preflight'], 'security_audit_preflight must be registered');
    assert.ok(registeredTools['security_audit_section_map'], 'security_audit_section_map must be registered');
    assert.ok(registeredTools['security_audit_scan_secrets'], 'security_audit_scan_secrets must be registered');
    assert.ok(registeredTools['security_audit_sast'], 'security_audit_sast must be registered');
    assert.ok(registeredTools['security_audit_scan_deps'], 'security_audit_scan_deps must be registered');
    assert.ok(registeredTools['security_audit_slop_check'], 'security_audit_slop_check must be registered');
    assert.ok(registeredTools['security_audit_calculate_score'], 'security_audit_calculate_score must be registered');
    assert.ok(registeredTools['security_audit_generate_report'], 'security_audit_generate_report must be registered');
    assert.ok(registeredTools['security_audit_get_reference'], 'security_audit_get_reference must be registered');

    // Verify prompt is registered
    const registeredPrompts = (server as any)._registeredPrompts;
    assert.ok(registeredPrompts['security-audit'], 'security-audit prompt must be registered');
  });
});
