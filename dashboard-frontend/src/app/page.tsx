"use client"

import { Shield, Activity, Map, Globe2, ArrowRight, Menu, X } from 'lucide-react';
import { useState } from 'react';
import Link from 'next/link';

export default function LandingPage() {
  const [menuOpen, setMenuOpen] = useState(false);

  const features = [
    {
      icon: Activity,
      title: "AI-Driven Responses",
      desc: "Transformer-based AI generates believable shell output in real-time, making the honeypot indistinguishable from a real server.",
      color: "cyan",
    },
    {
      icon: Globe2,
      title: "Attack Heatmap",
      desc: "Live geographical visualization of incoming attacks plotted on a world map with country-level granularity.",
      color: "red",
    },
    {
      icon: Map,
      title: "MITRE ATT&CK Mapping",
      desc: "Every attacker command is automatically mapped to 170+ MITRE ATT&CK techniques across all 14 tactics.",
      color: "purple",
    },
    {
      icon: Shield,
      title: "Threat Intelligence",
      desc: "Automated IOC extraction, session recording, and exportable reports for SOC ingestion and analysis.",
      color: "green",
    },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Nav */}
      <nav className="border-b border-slate-800 px-6 py-4">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6" />
            </div>
            <span className="text-lg font-semibold">AdaptiveWardens</span>
          </div>

          <div className="hidden md:flex items-center gap-6">
            <a href="#features" className="text-sm text-slate-400 hover:text-slate-200 transition-colors">Features</a>
            <a href="#architecture" className="text-sm text-slate-400 hover:text-slate-200 transition-colors">Architecture</a>
            <Link
              href="/login"
              className="flex items-center gap-2 px-5 py-2 bg-cyan-500/10 border border-cyan-500/20 rounded-lg text-cyan-400 hover:bg-cyan-500/20 transition-colors text-sm font-medium"
            >
              Launch Dashboard
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>

          <button className="md:hidden p-2 text-slate-400" onClick={() => setMenuOpen(!menuOpen)}>
            {menuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>

        {menuOpen && (
          <div className="md:hidden pt-4 pb-2 flex flex-col gap-3">
            <a href="#features" className="text-sm text-slate-400 py-1" onClick={() => setMenuOpen(false)}>Features</a>
            <a href="#architecture" className="text-sm text-slate-400 py-1" onClick={() => setMenuOpen(false)}>Architecture</a>
            <Link href="/login" className="text-sm text-cyan-400 py-1" onClick={() => setMenuOpen(false)}>Launch Dashboard</Link>
          </div>
        )}
      </nav>

      {/* Hero */}
      <section className="px-6 py-24 md:py-32">
        <div className="max-w-4xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 bg-cyan-500/10 border border-cyan-500/20 rounded-full text-xs text-cyan-400 mb-8">
            <span className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse" />
            Graduation Project — Zewail City of Science and Technology
          </div>

          <h1 className="text-4xl md:text-6xl font-bold leading-tight mb-6">
            Deceive Attackers.
            <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
              Collect Intelligence.
            </span>
            <br />
            Stay Ahead.
          </h1>

          <p className="text-lg text-slate-400 max-w-2xl mx-auto mb-10">
            An AI-driven adaptive honeypot that simulates realistic Linux and web environments
            to capture attacker behavior, extract threat intelligence, and map to MITRE ATT&CK
            in real-time.
          </p>

          <div className="flex items-center justify-center gap-4 flex-wrap">
            <Link
              href="/login"
              className="flex items-center gap-2 px-6 py-3 bg-cyan-500 hover:bg-cyan-600 rounded-lg text-white font-medium transition-colors"
            >
              Enter SOC Dashboard
              <ArrowRight className="w-4 h-4" />
            </Link>

            <a
              href="https://github.com/Aligithyb/-AdaptiveWardens"
              target="_blank"
              className="flex items-center gap-2 px-6 py-3 bg-slate-800 border border-slate-700 rounded-lg text-slate-300 hover:bg-slate-700 transition-colors"
            >
              <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
              GitHub
            </a>
          </div>
        </div>
      </section>

      {/* Terminal Preview */}
      <section className="px-6 pb-24">
        <div className="max-w-3xl mx-auto">
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
            <div className="flex items-center gap-2 px-4 py-3 bg-slate-800/50 border-b border-slate-800">
              <div className="w-3 h-3 bg-red-500 rounded-full" />
              <div className="w-3 h-3 bg-yellow-500 rounded-full" />
              <div className="w-3 h-3 bg-green-500 rounded-full" />
              <span className="text-xs text-slate-500 ml-2">SSH Session — attacker@api-prod-01</span>
            </div>
            <pre className="p-4 text-sm font-mono text-slate-300 overflow-x-auto">
              <span className="text-green-400">root@api-prod-01:~$</span> whoami{'\n'}
              root{'\n'}
              <span className="text-green-400">root@api-prod-01:~$</span> cat /etc/passwd{'\n'}
              root:x:0:0:root:/root:/bin/bash{'\n'}
              ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash{'\n'}
              deploy:x:1001:1001:Deploy:/home/deploy:/bin/bash{'\n'}
              <span className="text-green-400">root@api-prod-01:~$</span> <span className="animate-pulse">▊</span>
            </pre>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="px-6 pb-24">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-12">Key Features</h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {features.map((f, i) => {
              const Icon = f.icon;
              return (
                <div key={i} className="bg-slate-900 border border-slate-800 rounded-xl p-6 hover:border-slate-700 transition-colors">
                  <div className={`w-12 h-12 bg-${f.color}-500/10 rounded-lg flex items-center justify-center mb-4`}>
                    <Icon className={`w-6 h-6 text-${f.color}-400`} />
                  </div>
                  <h3 className="text-lg font-semibold mb-2">{f.title}</h3>
                  <p className="text-sm text-slate-400 leading-relaxed">{f.desc}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Architecture */}
      <section id="architecture" className="px-6 pb-24">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-12">System Architecture</h2>
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-8">
            <div className="flex flex-col items-center gap-4 text-sm">
              <div className="flex gap-8">
                <div className="px-6 py-3 bg-slate-800 border border-slate-700 rounded-lg text-slate-300">SSH Frontend</div>
                <div className="px-6 py-3 bg-slate-800 border border-slate-700 rounded-lg text-slate-300">HTTP Frontend</div>
              </div>
              <div className="text-slate-600">↓</div>
              <div className="px-6 py-3 bg-cyan-500/10 border border-cyan-500/20 rounded-lg text-cyan-400 font-medium">AI Engine</div>
              <div className="text-slate-600">↓</div>
              <div className="px-6 py-3 bg-slate-800 border border-slate-700 rounded-lg text-slate-300">Sandbox State Store</div>
              <div className="text-slate-600">↓</div>
              <div className="px-6 py-3 bg-purple-500/10 border border-purple-500/20 rounded-lg text-purple-400 font-medium">SOC Dashboard</div>
            </div>
          </div>
        </div>
      </section>

      {/* Team */}
      <section className="px-6 pb-24">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl font-bold mb-8">Team</h2>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { name: "Ali Ahmed Reda", id: "202201006" },
              { name: "Ali Nazeer", id: "202100732" },
              { name: "Ahmed Yasser", id: "202201883" },
              { name: "Abdulkhaliq Sarwat", id: "202202084" },
            ].map((m, i) => (
              <div key={i} className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <div className="w-12 h-12 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-full mx-auto mb-3" />
                <p className="text-sm font-medium">{m.name}</p>
                <p className="text-xs text-slate-500">{m.id}</p>
              </div>
            ))}
          </div>
          <p className="text-sm text-slate-500 mt-4">Supervised by Dr. Ashraf Hafez Badawi</p>
          <p className="text-sm text-slate-500">Zewail City of Science and Technology — CSAI Program</p>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800 px-6 py-6">
        <div className="max-w-6xl mx-auto flex items-center justify-between text-xs text-slate-600">
          <p>AdaptiveWardens — Graduation Project 2025–2026</p>
          <a href="https://github.com/Aligithyb/-AdaptiveWardens" target="_blank" className="hover:text-slate-400">GitHub</a>
        </div>
      </footer>
    </div>
  );
}
