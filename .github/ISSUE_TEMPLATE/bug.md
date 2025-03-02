name: 🐛 Bug Report
description: Report an issue that should be fixed

labels:
  - bug
  - needs triage

body:
  - type: markdown
    attributes:
      value: |
        Thank you for submitting a bug report.


  - type: input
    attributes:
      label: What version of zig?

      description: Copy the output of `zig version`
  - type: input
    attributes:
      label: What platform is your computer?       
  - type: textarea
    attributes:
      label: What steps can reproduce the bug?
      description: Explain the bug and provide a code snippet that can reproduce it.
    validations:

      required: true

  - type: textarea
    attributes:
      label: What is the expected behavior?
      description: If possible, please provide text instead of a screenshot.
  - type: textarea
    attributes:
      label: What do you see instead?
      description: If possible, please provide text instead of a screenshot.

  - type: textarea
    attributes:
      label: Additional information
      description: Is there anything else you think we should know?
