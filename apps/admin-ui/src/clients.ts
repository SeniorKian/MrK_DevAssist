import { registryEndpoints } from "./api";

export type ClientCommand = { label: string; ecosystem: "npm" | "pypi"; command: string; everyday: boolean };

/**
 * Client configuration commands for this appliance; `everyday` ones are shown in Simple mode.
 * `publicUrls` are the services' own public addresses (docs/35 `public_url`, from `usePublicServiceUrls()`);
 * without them the addresses are built from this page's location, as before.
 */
export function clientCommands(publicUrls: { npm?: string | null; pypi?: string | null } = {}): {
  endpoints: ReturnType<typeof registryEndpoints>;
  commands: ClientCommand[];
} {
  const endpoints = registryEndpoints(publicUrls);
  const pypiHost = (() => {
    try {
      return new URL(endpoints.pypi).hostname;
    } catch {
      return "";
    }
  })();
  // Plain-HTTP indexes must be marked trusted, otherwise pip/uv refuse them.
  const pipTrust = endpoints.portBased && pypiHost ? ` && pip config set global.trusted-host ${pypiHost}` : "";
  const uvTrust = endpoints.portBased && pypiHost ? ` --allow-insecure-host ${pypiHost}` : "";
  return {
    endpoints,
    commands: [
      { label: "npm", ecosystem: "npm", everyday: true, command: `npm config set registry ${endpoints.npm}` },
      { label: "pip", ecosystem: "pypi", everyday: true, command: `pip config set global.index-url ${endpoints.pypi}${pipTrust}` },
      { label: "uv", ecosystem: "pypi", everyday: true, command: `uv pip install <package> --index-url ${endpoints.pypi}${uvTrust}` },
      { label: "pnpm", ecosystem: "npm", everyday: false, command: `pnpm config set registry ${endpoints.npm}` },
      { label: "Yarn", ecosystem: "npm", everyday: false, command: `yarn config set npmRegistryServer ${endpoints.npm}` },
      { label: "Poetry", ecosystem: "pypi", everyday: false, command: `poetry source add --priority=primary mrk ${endpoints.pypi}` }
    ]
  };
}
