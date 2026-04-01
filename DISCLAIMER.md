# Disclaimer

Hermetic is provided "AS IS", without warranty of any kind, express or implied,
including but not limited to the warranties of merchantability, fitness for a
particular purpose, and noninfringement.

In no event shall the authors, contributors, or The Hermetic Project be liable
for any claim, damages, or other liability, whether in an action of contract,
tort, or otherwise, arising from, out of, or in connection with the software
or the use or other dealings in the software.

## Pre-Production Status

This software has not undergone an independent security audit by a third-party
firm. While the codebase has been verified through a comprehensive automated test suite,
multiple red team campaigns, and constitutional amendments under the HAIG governance
framework, it has zero production deployments at the time of initial release.

## Known Limitations

Hermetic publishes all known limitations openly. See the
[Known Limitations](README.md#scope) section of the README for
the complete list, including:

- Same-UID processes have full daemon access
- Pre-production software (zero production deployments)
- No independent third-party security audit
- Linux-only
- Containers require CAP_IPC_LOCK

## Credential Risk

Do not use Hermetic as the sole protection for production credentials without
understanding these limitations. For high-value credentials, use Hermetic
alongside your existing security practices, not as a replacement.

## Reveal Command

The `hermetic reveal` command outputs raw secret values to stdout. Once a
secret leaves Hermetic's protection boundary via reveal, Hermetic provides
no isolation guarantees. See [HC-14](docs/amendments/HC-14.md) for the
complete security model.

## License

This software is licensed under AGPL-3.0-or-later. See [LICENSE](LICENSE)
for the full text. Commercial licenses available at
[hermeticsys.com/license](https://hermeticsys.com/license).
