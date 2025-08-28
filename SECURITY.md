# Security Policy

## Supported Versions

Currently supported versions for security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability within GuardianEye, please follow these steps:

1. **Do Not** disclose the vulnerability publicly until it has been addressed.
2. Send details of the vulnerability to the project maintainers.
3. Include steps to reproduce the vulnerability if possible.
4. Allow reasonable time for the vulnerability to be patched before disclosure.

## Security Best Practices

When using GuardianEye:

1. **API Keys**: Never commit API keys to version control. Use environment variables:
   ```bash
   export GUARDIANEYE_VT_API_KEY="your-api-key"
   ```

2. **Test Files**: The EICAR test file is excluded from git by default. If you need to test malware detection, create test files in an isolated environment.

3. **Permissions**: Run GuardianEye with appropriate permissions. Avoid running as root unless necessary.

4. **Updates**: Keep GuardianEye and its dependencies updated to receive security patches.

5. **Logging**: Monitor log files for suspicious activity. Log files are stored in the `logs/` directory by default.

## Dependencies

GuardianEye uses several third-party packages. Keep these updated to their latest stable versions to ensure security patches are applied:

- requests
- typer
- rich
- yara-python

## Data Handling

GuardianEye processes files locally and can optionally send file hashes to VirusTotal for analysis. No complete files are transmitted to external services. 