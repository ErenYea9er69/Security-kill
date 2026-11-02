import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createServer } from '../src/server.js';

describe('MCP Server & Tools Suite', () => {
  it('should instantiate McpServer with all registered tools and resources and no legacy prompts', () => {
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

    // Verify no legacy prompt is registered
    const registeredPrompts = (server as any)._registeredPrompts;
    assert.strictEqual(registeredPrompts ? Object.keys(registeredPrompts).length : 0, 0);
  });
});
