# Go Server

This server uses gin framework, and has swagger setup.

## Table of Contents

- [Prerequisite](#prerequisite)
- [Installation](#installation)
- [Usage](#usage)

## Prerequisite

```bash
go install github.com/cosmtrek/air@latest
go install github.com/swaggo/swag/cmd/swag@latest
```

## Installation

```bash
go tidy
```

## Usage

```bash
air
```

Once you see the `[GIN-debug] Listening and serving HTTP on :8080`, you can visit <http://localhost:9090/docs/index.html> for OpenAPI v2 docs.
