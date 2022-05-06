# Conventions for OSD Containers

This convention is suitable for standalone containers - if an operator is desired other conventions should be used.

> Note: The repository's main `Makefile` needs to be edited to have the following line:

```make
include boilerplate/generated-includes.mk
```

## `make` targets and functions

The provided `Makefile` will build and push a container image defined by a Dockerfile at `build/Dockerfile`. If multiple containers are contained in the repo, they can also be managed by defining an `ADDITIONAL_IMAGE_SPECS` variable like so:

```make
define ADDITIONAL_IMAGE_SPECS
./path/to/a/Dockerfile $(IMAGE_REGISTRY)/$(IMAGE_REPOSITORY)/a-image:v1.2.3
./path/to/b/Dockerfile $(IMAGE_REGISTRY)/$(IMAGE_REPOSITORY)/b-image:v4.5.6
endef
```

| Makefile target | Description |
|---|---|
| `make osd-container-image-build` | Build the default container at `build/Dockerfile` and tag it based on the commit. Specify `DOCKERFILE` and `IMAGE_URI` to build other containers. |
| `make osd-container-image-push` | Push the default container. |
| `make osd-container-image-build-push` | Build and push the default container and `ADDITIONAL_IMAGE_SPECS`. Meant to be run by app-interface. |
| `make isclean` | Ensure the local git checkout is clean. |
| `make prow-config` | Updates the corresponding Prow config file in [openshift/release](https://github.com/openshift/release) to run `make test` on merge requests. This `test` make target should be defined by the consumer. If this is a new repository it should be onboarded to openshift/release first before this is run. |

## Linting/Testing

This boilerplate convention does not contain any linting or testing guidelines to support a variety of containers. Those `Makefile` targets should be defined by the consumer themselves.
