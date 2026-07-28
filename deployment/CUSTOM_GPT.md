# Custom GPT deployment

1. Create a GPT in the web editor.
2. Paste `agent/CUSTOM_GPT_INSTRUCTIONS.md` into Instructions.
3. Upload the ten curated files in `knowledge/` as reference material.
4. Enable only necessary capabilities.
5. Choose **either Apps or Actions**. For this release candidate, Actions are the intended profile; disable Apps.
6. Replace the OpenAPI server placeholder and configure API-key or OAuth authentication in the editor.
7. Provide a valid privacy-policy URL if the GPT will be shared publicly with Actions.
8. Verify workspace action-domain allowlists.
9. Test in Preview before sharing. Start with instructions and examples before adding more tools.
10. Run the acceptance bank and injection cases, then publish only to a restricted audience.

The bundled Action is advisory-only. It cannot execute an external write or commit memory. A successful upload or Preview response is not a live effect receipt.
