/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'http://dashboard-backend:8003/api/:path*',
      },
    ]
  },
}

export default nextConfig
