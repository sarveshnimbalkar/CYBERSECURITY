'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { fetchDemoScenarios, runDemoSimulation, runAllSimulations, fetchModelStatus, seedBaseline, trainDemoModel, DemoScenario, ModelStatus } from '@/lib/api';
import { PlayCircle, Zap, CheckCircle2, ArrowRight } from 'lucide-react';
import { SeverityBadge } from '@/components/Badges';

export default function DemoPage() {
  const [scenarios, setScenarios] = useState<DemoScenario[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeSimulation, setActiveSimulation] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<Record<string, unknown> | null>(null);
  const [model, setModel] = useState<ModelStatus | null>(null);
  const [demoAvailable, setDemoAvailable] = useState(true);

  useEffect(() => {
    fetchDemoScenarios()
      .then(setScenarios)
      .catch(() => setDemoAvailable(false))
      .finally(() => setLoading(false));
    fetchModelStatus().then(setModel).catch(() => setModel(null));
  }, []);

  const handleSimulate = async (id: string) => {
    setActiveSimulation(id);
    setLastResult(null);
    try {
      const res = await runDemoSimulation(id);
      setLastResult(res);
    } catch (e: unknown) {
      console.error('Simulation failed:', e);
      setLastResult({ error: e instanceof Error ? e.message : 'Simulation failed' });
    } finally {
      setActiveSimulation(null);
    }
  };

  const handleSimulateAll = async () => {
    setActiveSimulation('ALL');
    setLastResult(null);
    try {
      const res = await runAllSimulations();
      setLastResult(res);
    } catch (e: unknown) {
      console.error('Simulation failed:', e);
      setLastResult({ error: e instanceof Error ? e.message : 'Simulation failed' });
    } finally {
      setActiveSimulation(null);
    }
  };

  const handleTrainModel = async () => {
    setActiveSimulation('TRAIN');
    setLastResult(null);
    try {
      await seedBaseline();
      const status = await trainDemoModel();
      setModel(status);
      setLastResult({ model: 'Isolation Forest', ...status });
    } catch (e: unknown) {
      setLastResult({ error: e instanceof Error ? e.message : 'Model training failed' });
    } finally {
      setActiveSimulation(null);
    }
  };

  return (
    <div className="space-y-6">
      {!demoAvailable && <div className="p-4 rounded-xl border border-amber-700 text-amber-300 text-sm">Demo mode is disabled on this server.</div>}
      {/* Top Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-amber-950/40 via-slate-900 to-indigo-950/40 border border-amber-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-amber-400" />
            <h2 className="text-xl font-bold text-slate-100">Academic Demo Mode & Attack Simulator</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Generate synthetic event records to demonstrate detection and incident triage.
          </p>
        </div>

        <button
          onClick={handleSimulateAll}
          disabled={activeSimulation !== null}
          className="px-5 py-2.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs transition flex items-center gap-2 disabled:opacity-50 shrink-0 shadow-lg shadow-amber-500/20"
        >
          <PlayCircle className={`w-4 h-4 fill-current ${activeSimulation === 'ALL' ? 'animate-spin' : ''}`} />
          {activeSimulation === 'ALL' ? 'Simulating All Scenarios...' : `Run All ${scenarios.length} Scenarios`}
        </button>
      </div>

      <div className="p-5 rounded-xl border border-indigo-800/50 bg-indigo-950/20 flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">Optional anomaly model</h3>
          <p className="text-xs text-slate-400 mt-1">
            {model?.trained
              ? `Trained on ${model.baseline_events} ${model.baseline_source} events. Synthetic baseline is for demonstration only.`
              : 'No trained model loaded. Rules still run without it.'}
          </p>
        </div>
        <button onClick={handleTrainModel} disabled={activeSimulation !== null}
          className="px-4 py-2 rounded-lg bg-indigo-500 text-white text-xs font-semibold disabled:opacity-50">
          {activeSimulation === 'TRAIN' ? 'Training...' : 'Seed benign events & train model'}
        </button>
      </div>

      {/* Simulation Result Alert */}
      {lastResult && (
        <div className="p-4 rounded-xl border border-emerald-500/40 bg-emerald-950/30 text-xs font-mono text-emerald-300 space-y-2">
          <div className="flex items-center justify-between font-bold text-sm">
            <span className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              {lastResult.error ? 'Operation Failed' : 'Operation Completed'}
            </span>
            <Link href="/incidents" className="text-cyan-400 hover:underline font-normal text-xs flex items-center gap-1">
              View Generated Incidents <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          <pre className="text-[11px] bg-slate-950/80 p-3 rounded-lg border border-slate-800 text-slate-300 overflow-x-auto">
            {JSON.stringify(lastResult, null, 2)}
          </pre>
        </div>
      )}

      {/* Scenarios Grid */}
      {loading ? (
        <div className="p-12 text-center text-slate-400 text-sm">
          <div className="inline-block w-5 h-5 border-2 border-amber-400 border-t-transparent rounded-full animate-spin mr-2" />
          Loading simulation scenarios...
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {scenarios.map((sc) => (
            <div
              key={sc.id}
              className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur space-y-4 flex flex-col justify-between hover:border-amber-500/40 transition group"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <SeverityBadge severity={sc.expected_severity} />
                  <span className="text-[10px] font-mono text-slate-500">ID: {sc.id}</span>
                </div>

                <h3 className="font-bold text-slate-100 text-sm group-hover:text-amber-300 transition">
                  {sc.name}
                </h3>
                <p className="text-xs text-slate-400">{sc.description}</p>
              </div>

              <div className="space-y-3 pt-3 border-t border-slate-800/80">
                <div className="text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
                  <span className="text-slate-500">Triggers:</span>
                  <span className="text-cyan-400 font-bold">{sc.expected_rules.join(', ')}</span>
                </div>

                <button
                  onClick={() => handleSimulate(sc.id)}
                  disabled={activeSimulation !== null}
                  className="w-full py-2 rounded-lg bg-slate-800 hover:bg-amber-500/20 hover:text-amber-300 hover:border-amber-500/40 border border-slate-700 text-xs font-semibold text-slate-200 transition flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  <PlayCircle className={`w-3.5 h-3.5 ${activeSimulation === sc.id ? 'animate-spin' : ''}`} />
                  {activeSimulation === sc.id ? 'Simulating...' : 'Run Scenario'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
