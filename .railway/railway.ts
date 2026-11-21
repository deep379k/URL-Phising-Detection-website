import { defineRailway, github, project, service } from "railway/iac";
// This repository manages only its own resources in the environment. Other
// repositories export their own partial name.
// See https://docs.railway.com/infrastructure-as-code#multi-repo-projects
export const partial = "phishguard-web";
export default defineRailway(() => {
  const phishguardWeb = service("phishguard-web", {
    source: github("deep379k/URL-Phising-Detection-website"),
    build: { buildEnvironment: "V3", builder: "DOCKERFILE", dockerfilePath: "Dockerfile" },
    healthcheck: "/api/health",
    healthcheckTimeout: 180,
    replicas: { "iad": 1 },
  });

  return project("phishguard-ai", {
    variables: { managed: false },
    resources: [phishguardWeb],
  });
});
