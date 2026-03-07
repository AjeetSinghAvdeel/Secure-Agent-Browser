import React from 'react';
import GaugeChart from 'react-gauge-component';
import { CheckCircle, AlertTriangle, AlertCircle, TrendingUp, Shield } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

interface RiskIndicator {
  name: string;
  detected: boolean;
  severity?: 'low' | 'medium' | 'high' | 'critical';
}

interface ExplanationData {
  summary: string;
  reasons?: string[];
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
  // Determine trust score color
  const getTrustColor = (score: number): { bar: string; text: string; bg: string } => {
    if (score > 80) return { bar: 'bg-green-500', text: 'text-green-700', bg: 'bg-green-50' };
    if (score >= 40) return { bar: 'bg-yellow-500', text: 'text-yellow-700', bg: 'bg-yellow-50' };
    return { bar: 'bg-red-500', text: 'text-red-700', bg: 'bg-red-50' };
  };

  // Determine trust label
  const getTrustLabel = (score: number): string => {
    if (score > 80) return 'High Trust';
    if (score >= 40) return 'Medium Trust';
    return 'Low Trust';
  };

  // Determine decision styling
  const getDecisionStyle = (
    dec: string
  ): {
    color: string;
    bgColor: string;
    icon: React.ReactNode;
    description: string;
  } => {
    switch (dec) {
      case 'ALLOW':
        return {
          color: 'text-green-600',
          bgColor: 'bg-green-100',
          icon: <CheckCircle className="w-6 h-6" />,
          description: 'Safe to proceed'
        };
      case 'WARN':
        return {
          color: 'text-yellow-600',
          bgColor: 'bg-yellow-100',
          icon: <AlertTriangle className="w-6 h-6" />,
          description: 'Proceed with caution'
        };
      case 'BLOCK':
        return {
          color: 'text-red-600',
          bgColor: 'bg-red-100',
          icon: <AlertCircle className="w-6 h-6" />,
          description: 'Access blocked'
        };
      default:
        return {
          color: 'text-gray-600',
          bgColor: 'bg-gray-100',
          icon: <Shield className="w-6 h-6" />,
          description: 'Unknown status'
        };
    }
  };

  const decisionStyle = getDecisionStyle(decision);
  const trustColors = getTrustColor(trustScore);
  const detectedIndicators = indicators.filter(ind => ind.detected);

  // Severity color mapping
  const severityColors: { [key: string]: string } = {
    critical: 'bg-red-100 text-red-800 border-red-300',
    high: 'bg-orange-100 text-orange-800 border-orange-300',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-300',
    low: 'bg-blue-100 text-blue-800 border-blue-300'
  };

  return (
    <Card className="w-full border-2 shadow-lg">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-600 to-blue-700 text-white p-4 md:p-6 flex items-center justify-between rounded-t-lg">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6" />
          <h2 className="text-xl md:text-2xl font-bold">Risk Intelligence Panel</h2>
        </div>
        <TrendingUp className="w-6 h-6 opacity-70" />
      </div>

      {/* Content */}
      <div className="p-4 md:p-6 space-y-6">
        {/* Top Row: Risk Gauge + Trust Score + Decision */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 md:gap-6">
          {/* Risk Score Gauge */}
          <div className="flex flex-col items-center justify-center p-4 bg-gray-50 rounded-lg border-2 border-gray-200">
            <h3 className="text-xs font-semibold text-gray-600 uppercase tracking-wider mb-3">
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
              <p className="text-2xl font-bold text-gray-900">{riskScore}</p>
              <p className="text-xs text-gray-600">out of 100</p>
            </div>
          </div>

          {/* Trust Score */}
          <div className="flex flex-col justify-center p-4 bg-gray-50 rounded-lg border-2 border-gray-200">
            <h3 className="text-xs font-semibold text-gray-600 uppercase tracking-wider mb-3">
              Domain Trust
            </h3>
            <div className="flex-grow flex flex-col justify-center">
              <div className="mb-4">
                <div className="flex justify-between items-center mb-2">
                  <span className={`text-sm font-bold ${trustColors.text}`}>
                    {getTrustLabel(trustScore)}
                  </span>
                  <span className="text-lg font-bold text-gray-900">{trustScore}%</span>
                </div>
                <div className="w-full bg-gray-300 rounded-full h-3 overflow-hidden">
                  <div
                    className={`${trustColors.bar} h-3 rounded-full transition-all duration-500`}
                    style={{ width: `${trustScore}%` }}
                  />
                </div>
              </div>

              {/* Trust Status Indicator */}
              <div className={`${trustColors.bg} p-3 rounded border-l-4 ${trustColors.bar}`}>
                <p className={`text-xs font-medium ${trustColors.text}`}>
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
          <div className="flex flex-col items-center justify-center p-4 bg-gray-50 rounded-lg border-2 border-gray-200">
            <h3 className="text-xs font-semibold text-gray-600 uppercase tracking-wider mb-3 w-full text-center">
              Security Decision
            </h3>
            <div className={`p-4 rounded-full ${decisionStyle.bgColor} mb-3`}>
              <div className={`${decisionStyle.color}`}>{decisionStyle.icon}</div>
            </div>
            <p className={`text-2xl font-bold ${decisionStyle.color}`}>{decision}</p>
            <p className="text-xs text-gray-600 text-center mt-2">{decisionStyle.description}</p>
          </div>
        </div>

        {/* Attack Indicators Section */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-gray-900 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-orange-600" />
            Detected Signals
            {detectedIndicators.length > 0 && (
              <Badge className="ml-2 bg-red-100 text-red-800 border-red-300">
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
                    {indicator.severity && (
                      <p className="text-xs opacity-75 mt-1 capitalize">{indicator.severity}</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-4 bg-green-50 rounded-lg border-2 border-green-200 flex items-center gap-3">
              <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0" />
              <p className="text-green-800 font-medium text-sm">No attack signals detected</p>
            </div>
          )}
        </div>

        {/* Explanation Summary */}
        <div className="space-y-3 bg-blue-50 border-2 border-blue-200 p-4 rounded-lg">
          <div className="flex items-start gap-3">
            <div className="w-6 h-6 rounded-full bg-blue-600 text-white flex items-center justify-center flex-shrink-0 mt-0.5 text-xs font-bold">
              i
            </div>
            <div className="flex-1">
              <h4 className="text-xs font-semibold text-blue-900 uppercase tracking-wider mb-2">
                AI Analysis
              </h4>
              <p className="text-sm text-blue-900 leading-relaxed font-medium">
                {explanation.summary}
              </p>

              {/* Detailed Reasons */}
              {explanation.reasons && explanation.reasons.length > 0 && (
                <div className="mt-3 space-y-2">
                  <p className="text-xs font-semibold text-blue-800 uppercase">Key Findings:</p>
                  <ul className="space-y-1 text-xs text-blue-800">
                    {explanation.reasons.slice(0, 3).map((reason, index) => (
                      <li key={index} className="flex gap-2 ml-2">
                        <span className="font-bold flex-shrink-0">•</span>
                        <span>{reason}</span>
                      </li>
                    ))}
                    {explanation.reasons.length > 3 && (
                      <li className="text-blue-700 font-semibold ml-2">
                        + {explanation.reasons.length - 3} more findings
                      </li>
                    )}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Quick Stats Footer */}
        <div className="grid grid-cols-3 gap-3 pt-3 border-t-2 border-gray-200">
          <div className="text-center p-2 bg-gray-50 rounded">
            <p className="text-xs font-semibold text-gray-600 uppercase">Risk Level</p>
            <p className={`text-lg font-bold mt-1 ${
              riskScore >= 70 ? 'text-red-600' :
              riskScore >= 40 ? 'text-yellow-600' :
              'text-green-600'
            }`}>
              {riskScore >= 70 ? 'HIGH' : riskScore >= 40 ? 'MED' : 'LOW'}
            </p>
          </div>
          <div className="text-center p-2 bg-gray-50 rounded">
            <p className="text-xs font-semibold text-gray-600 uppercase">Signals</p>
            <p className="text-lg font-bold mt-1 text-gray-900">{detectedIndicators.length}</p>
          </div>
          <div className="text-center p-2 bg-gray-50 rounded">
            <p className="text-xs font-semibold text-gray-600 uppercase">Decision</p>
            <p className={`text-lg font-bold mt-1 ${decisionStyle.color}`}>{decision}</p>
          </div>
        </div>
      </div>
    </Card>
  );
};

export default RiskIntelligencePanel;
