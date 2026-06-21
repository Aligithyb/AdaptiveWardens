'use client';
import { useId } from 'react';

export function BrandLogo({ size = 40 }: { size?: number }) {
  const uid = useId().replace(/:/g, '');
  const g1 = `aw-g1-${uid}`;
  const g2 = `aw-g2-${uid}`;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 44 44"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="AdaptiveWardens logo"
    >
      <defs>
        <linearGradient id={g1} x1="0" y1="0" x2="44" y2="44" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#06b6d4" />
          <stop offset="100%" stopColor="#1e40af" />
        </linearGradient>
        <linearGradient id={g2} x1="0" y1="0" x2="44" y2="44" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#67e8f9" stopOpacity="0.25" />
          <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.05" />
        </linearGradient>
      </defs>

      {/* Outer hexagon */}
      <path d="M22 2L39 12V32L22 42L5 32V12L22 2Z" fill={`url(#${g1})`} />

      {/* Inner hex ring for depth */}
      <path
        d="M22 7.5L35 15V29L22 36.5L9 29V15L22 7.5Z"
        fill={`url(#${g2})`}
        stroke="rgba(255,255,255,0.22)"
        strokeWidth="0.6"
      />

      {/* AW monogram: two A-peaks forming a W */}
      <path
        d="M13 15.5L17.5 28.5L22 20L26.5 28.5L31 15.5"
        stroke="white"
        strokeWidth="2.3"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
        opacity="0.95"
      />

      {/* Cyan scan-line accent */}
      <line x1="14" y1="25" x2="30" y2="25" stroke="#67e8f9" strokeWidth="0.9" strokeOpacity="0.55" />
    </svg>
  );
}
