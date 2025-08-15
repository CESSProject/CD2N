# README

The Justicar Docker container requires a host path to be mounted (e.g., '/opt/justicar'). Important runtime configuration files will be stored in this host directory. Every time we upgrade the Justicar Docker image, the same host path must be mounted to the container because Justicar needs to transfer data and state from the previous version. The structure of the mounted host path is as follows:

.
├── backups
│   ├── 1
│   │   └── ["version1"]
│   └── 2
│       └── ["version2"]
├── current -> /opt/justicar/backups/2
└── release
    └── ["release version"]

The `backups` directory is stored on the host. The `current` directory is a symbolic link that will be created when the Docker container is running. The `release` directory contains the release version of Justicar, bundled with the new Docker image and published.