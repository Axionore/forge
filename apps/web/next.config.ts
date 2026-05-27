import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Security & production hardening
  poweredByHeader: false,
  reactStrictMode: true,

  // Recommended for production
  compress: true,

  // Experimental / future features
  experimental: {
    // Enable when stable and useful
    // typedRoutes: true,
  },

  // Headers for security (can be expanded)
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          {
            key: "X-Content-Type-Options",
            value: "nosniff",
          },
          {
            key: "X-Frame-Options",
            value: "DENY",
          },
          {
            key: "Referrer-Policy",
            value: "strict-origin-when-cross-origin",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
