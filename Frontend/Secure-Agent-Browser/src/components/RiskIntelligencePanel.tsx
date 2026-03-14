import React from 'react';
import GaugeChart from 'react-gauge-component';
import { CheckCircle, AlertTriangle, AlertCircle, TrendingUp, Shield } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

interface RiskIndicator {
  name: string;
  detected: boolean;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  confidence?: 'low' | 'medium' | 'high' | 'critical';
}

interface ExplanationData {
  summary: string;
  reasons?: string[];
  policyDecision?: string;
}

interface RiskIntelligencePanelProps {
  riskScore: number; // 0-100
  trustScore: number; // 0-100
  decision: 'ALLOW' | 'WARN' | 'BLOCK';
  indicators: RiskIndicator[];
  explanation: ExplanationData;
}

/**
 * RiskIntelligencePanel Component
 * 
 * Displays key risk metrics including gauge-based risk score, trust indicators,
 * policy decisions, detected attack signals, and AI-generated explanations.
 */
const RiskIntelligencePanel: React.FC<RiskIntelligencePanelProps> = ({
  riskScore,
  trustScore,
  decision,
  indicators,
  explanation
}) => {
  const getTrustColor = (
    score: number
  ): { bar: string; text: string; bg: string; ring: string } => {
    if (score > 80) {
      return {
        bar: 'bg-cyber-safe',
        text: 'text-cyber-safe',
        bg: 'bg-cyber-safe/10',
        ring: 'border-cyber-safe/30',
      };
    }
    if (score >= 40) {
      return {
        bar: 'bg-cyber-warning',
        text: 'text-cyber-warning',
        bg: 'bg-cyber-warning/10',
        ring: 'border-cyber-warning/30',
      };
    }
    return {
      bar: 'bg-cyber-danger',
      text: 'text-cyber-danger',
      bg: 'bg-cyber-danger/10',
      ring: 'border-cyber-danger/30',
    };
  };

  const getTrustLabel = (score: number): string => {
    if (score > 80) return 'High Trust';
    if (score >= 40) return 'Medium Trust';
    return 'Low Trust';
  };

  const getDecisionStyle = (
    dec: string
  ): {
    color: string;
    bgColor: string;
    ring: string;
    icon: React.ReactNode;
    description: string;
  } => {
    switch (dec) {
      case 'ALLOW':
        return {
          color: 'text-cyber-safe',
          bgColor: 'bg-cyber-safe/15',
          ring: 'border-cyber-safe/30',
          icon: <CheckCircle className="w-6 h-6" />,
          description: 'Safe to proceed'
        };
      case 'WARN':
        return {
          color: 'text-cyber-warning',
          bgColor: 'bg-cyber-warning/15',
          ring: 'border-cyber-warning/30',
          icon: <AlertTriangle className="w-6 h-6" />,
          description: 'Proceed with caution'
        };
      case 'BLOCK':
        return {
          color: 'text-cyber-danger',
          bgColor: 'bg-cyber-danger/15',
          ring: 'border-cyber-danger/30',
          icon: <AlertCircle className="w-6 h-6" />,
          description: 'Access blocked'
        };
      default:
        return {
          color: 'text-muted-foreground',
          bgColor: 'bg-secondary/60',
          ring: 'border-border',
          icon: <Shield className="w-6 h-6" />,
          description: 'Unknown status'
        };
    }
  };

  const decisionStyle = getDecisionStyle(decision);
  const trustColors = getTrustColor(trustScore);
  const detectedIndicators = indicators.filter(ind => ind.detected);

  const severityColors: { [key: string]: string } = {
    critical: 'bg-cyber-danger/20 text-red-200 border-cyber-danger/40',
    high: 'bg-orange-500/15 text-orange-200 border-orange-400/40',
    medium: 'bg-cyber-warning/15 text-yellow-100 border-cyber-warning/40',
    low: 'bg-primary/15 text-cyan-100 border-primary/40'
  };

  return (
    <Card className="w-full overflow-hidden border border-cyber-glass-border/80 bg-gradient-to-b from-cyber-glass/70 to-background/70 shadow-xl backdrop-blur-sm">
      {/* Header */}
      <div className="bg-gradient-to-r from-primary/30 via-primary/20 to-accent/20 border-b border-cyber-glass-border p-4 md:p-5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-primary" />
          <h2 className="text-lg md:text-xl font-semibold text-foreground">Risk Intelligence Panel</h2>
        </div>
        <TrendingUp className="w-5 h-5 text-primary/80" />
      </div>

      {/* Content */}
      <div className="p-4 md:p-6 space-y-6">
        {/* Top Row: Risk Gauge + Trust Score + Decision */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 md:gap-6">
          {/* Risk Score Gauge */}
          <div className="flex flex-col items-center justify-center p-4 bg-secondary/40 rounded-xl border border-border">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
              Risk Score
            </h3>
            <div className="w-full flex justify-center">
              <GaugeChart
                type="semicircle"
                arc={{
                  subArcs: [
                    { limit: 33, color: '#22c55e' },
                    { limit: 67, color: '#eab308' },
                    { limit: 100, color: '#ef4444' }
                  ]
                }}
                value={riskScore}
                style={{ width: '100%', maxWidth: '200px' }}
              />
            </div>
            <div className="text-center mt-2">
              <p className="text-3xl font-bold text-foreground">{riskScore}</p>
              <p className="text-xs text-muted-foreground">out of 100</p>
            </div>
          </div>

          {/* Trust Score */}
          <div className="flex flex-col justify-center p-4 bg-secondary/40 rounded-xl border border-border">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
              Domain Trust
            </h3>
            <div className="flex-grow flex flex-col justify-center">
              <div className="mb-4">
                <div className="flex justify-between items-center mb-2">
                  <span className={`text-sm font-bold ${trustColors.text}`}>
                    {getTrustLabel(trustScore)}
                  </span>
                  <span className="text-2xl font-semibold text-foreground">{trustScore}%</span>
                </div>
                <div className="w-full bg-muted rounded-full h-2.5 overflow-hidden">
                  <div
                    className={`${trustColors.bar} h-3 rounded-full transition-all duration-500`}
                    style={{ width: `${trustScore}%` }}
                  />
                </div>
              </div>

              {/* Trust Status Indicator */}
              <div className={`${trustColors.bg} ${trustColors.ring} p-3 rounded-lg border`}>
                <p className={`text-xs font-medium leading-relaxed ${trustColors.text}`}>
                  {trustScore > 80
                    ? 'Domain appears legitimate and trustworthy'
                    : trustScore >= 40
                    ? 'Domain has some concerning indicators'
                    : 'Domain shows multiple risk factors'}
                </p>
              </div>
            </div>
          </div>

          {/* Security Decision Badge */}
          <div className={`flex flex-col items-center justify-center p-4 rounded-xl border bg-secondary/40 ${decisionStyle.ring}`}>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 w-full text-center">
              Security Decision
            </h3>
            <div className={`p-4 rounded-full ${decisionStyle.bgColor} border ${decisionStyle.ring} mb-3`}>
              <div className={`${decisionStyle.color}`}>{decisionStyle.icon}</div>
            </div>
            <p className={`text-2xl font-bold ${decisionStyle.color}`}>{decision}</p>
            <p className="text-xs text-muted-foreground text-center mt-2">{decisionStyle.description}</p>
          </div>
        </div>

        {/* Attack Indicators Section */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-cyber-warning" />
            Detected Signals
            {detectedIndicators.length > 0 && (
              <Badge className="ml-2 bg-cyber-danger/20 text-red-200 border-cyber-danger/40">
                {detectedIndicators.length} detected
              </Badge>
            )}
          </h3>

          {detectedIndicators.length > 0 ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
              {detectedIndicators.map((indicator, index) => (
                <div
                  key={index}
                  className={`p-3 rounded-lg border-2 flex items-start gap-2 ${
                    severityColors[indicator.severity || 'medium']
                  }`}
                >
                  <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="font-semibold text-sm leading-tight">
                      {indicator.name.replace(/_/g, ' ')}
                    </p>
                    <p className="text-xs opacity-75 mt-1 capitalize">
                      {indicator.severity || 'low'}
                      {indicator.confidence ? ` • confidence ${indicator.confidence}` : ''}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-4 bg-cyber-safe/10 rounded-lg border border-cyber-safe/30 flex items-center gap-3">
              <CheckCircle className="w-5 h-5 text-cyber-safe flex-shrink-0" />
              <p className="text-cyber-safe font-medium text-sm">No attack signals detected</p>
            </div>
          )}
        </div>

        {/* Explanation Summary */}
        <div className="space-y-3 bg-primary/10 border border-primary/30 p-4 rounded-lg">
          <div className="flex items-start gap-3">
            <div className="w-6 h-6 rounded-full bg-primary text-primary-foreground flex items-center justify-center flex-shrink-0 mt-0.5 text-xs font-bold">
              i
            </div>
            <div className="flex-1">
              <h4 className="text-xs font-semibold text-primary uppercase tracking-wider mb-2">
                AI Analysis
              </h4>
              <p className="text-sm text-foreground leading-relaxed font-medium">
                {explanation.summary}
              </p>

              {/* Detailed Reasons */}
              {explanation.reasons && explanation.reasons.length > 0 && (
                <div className="mt-3 space-y-2">
                  <p className="text-xs font-semibold text-primary uppercase">Key Findings:</p>
                  <ul className="space-y-1 text-xs text-foreground">
                    {explanation.reasons.slice(0, 3).map((reason, index) => (
                      <li key={index} className="flex gap-2 ml-2">
                        <span className="font-bold flex-shrink-0 text-primary">•</span>
                        <span>{reason}</span>
                      </li>
                    ))}
                    {explanation.reasons.length > 3 && (
                      <li className="text-primary font-semibold ml-2">
                        + {explanation.reasons.length - 3} more findings
                      </li>
                    )}
                  </ul>
                </div>
              )}
              <div className="mt-3">
                <p className="text-xs font-semibold text-primary uppercase">Policy Decision:</p>
                <p className="text-sm text-foreground mt-1 font-semibold">
                  {explanation.policyDecision || decision}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Quick Stats Footer */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-3 border-t border-border">
          <div className="text-center p-3 bg-secondary/40 rounded-lg border border-border">
            <p className="text-xs font-semibold text-muted-foreground uppercase">Risk Level</p>
            <p className={`text-lg font-bold mt-1 ${
              riskScore >= 70 ? 'text-cyber-danger' :
              riskScore >= 40 ? 'text-cyber-warning' :
              'text-cyber-safe'
            }`}>
              {riskScore >= 70 ? 'HIGH' : riskScore >= 40 ? 'MED' : 'LOW'}
            </p>
          </div>
          <div className="text-center p-3 bg-secondary/40 rounded-lg border border-border">
            <p className="text-xs font-semibold text-muted-foreground uppercase">Signals</p>
            <p className="text-lg font-bold mt-1 text-foreground">{detectedIndicators.length}</p>
          </div>
          <div className="text-center p-3 bg-secondary/40 rounded-lg border border-border">
            <p className="text-xs font-semibold text-muted-foreground uppercase">Decision</p>
            <p className={`text-lg font-bold mt-1 ${decisionStyle.color}`}>{decision}</p>
          </div>
        </div>
      </div>
    </Card>
  );
};

export default RiskIntelligencePanel;
