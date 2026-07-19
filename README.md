# Claude Resumer

Source code for Claude Resumer, a native macOS menu-bar app that watches for Claude rate-limit ("session limit") messages and, once the named reset time has passed, automatically re-sends a short "continue where you left off" prompt to the sessions you choose.

This repository is published so the code can be read and audited. The finished app, signed and notarized with automatic updates, is available at [clauderesumer.com](https://clauderesumer.com).

It covers four sources:

- the Claude extension for VS Code
- the Claude CLI
- plain Claude App chats
- Code sessions inside the Claude App

The app uses the macOS Accessibility API to focus the right window, fill the resume prompt, and press Enter. Claude CLI sessions are resumed only through an existing Terminal or VS Code terminal process. Claude Resumer never starts a Claude process itself and never opens a project directory itself.

> Not affiliated with or endorsed by Anthropic. Claude Resumer never bypasses Claude's permission prompts or safety checks.

## How resuming works

A session is only resumed when a rate-limit entry is the last relevant activity and the named reset time has passed, plus a short grace period. Detection matches Claude's literal limit text.

VS Code chats are selected through the Claude Extension deep link and resumed using Accessibility. Claude App and Claude App Code are also controlled using Accessibility. If the original Claude CLI process is no longer running, Claude Resumer reports that the session must be reopened manually instead of launching a child process.

The resume prompt is a single editable line, default: `Ga door met de taak vanaf waar je werd onderbroken.`

## Closed-lid mode

An optional advanced mode keeps the app running with the MacBook lid shut, using `pmset disablesleep` and Low Power Mode. It requests admin rights, restores your original power settings on exit, and stops on serious thermal pressure or at 10% battery.

## Localization

English, Dutch, Spanish, French, German, Portuguese, Simplified Chinese, and Russian, following the macOS language automatically.

## Support

Building from source is free and always will be. If Claude Resumer is useful to you, you can support the solo developer with a coffee: [buymeacoffee.com/socialista](https://buymeacoffee.com/socialista).

## License

[GPL-3.0](LICENSE).
