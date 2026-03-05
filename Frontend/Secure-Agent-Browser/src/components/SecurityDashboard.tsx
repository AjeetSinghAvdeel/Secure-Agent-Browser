import React from 'react';
import { PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { AlertCircle, CheckCircle, AlertTriangle, Shield, TrendingDown } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';

interface AttackIndicator {
  name: string;
  detected: boolean;
  severity?: 'low' | 'medium' | 'high' | 'critical';
}

interface ExplanationData {
  summary: string;
  reasons: string[];
  risk_level?: string;
  recommended_action?: string;
}

interface SecurityDashboardProps {
  riskScore: number; // 0-100
  trustScore: number; // 0-100
  decision: 'ALLOW' | 'WARN' | 'BLOCK';
  attackIndicators: AttackIndicator[];
  explanation: ExplanationData;
}

/**
 * SecurityDashboard Component
 * 
 * Visualizes security scan results including risk scores, trust indicators,
 * security decisions, detected attacks, and explainability insights.
 */
const SecurityDashboard: React.FC<SecurityDashboardProps> = ({
  riskScore,
  trustScore,
  decision,
  attackIndicators,
  explanation
}) => {
  // Get color based on trust score
  const getTrustColor = (score: number): string => {
    if (score >= 70) return 'text-green-600';
    if (score >= 40) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getTrustBgColor = (score: number): string => {
    if (score >= 70) return 'bg-green-100';
    if (score >= 40) return 'bg-yellow-100';
    return 'bg-red-100';
  };

  const getTrustBgColorFill = (score: number): string => {
    if (score >= 70) return 'bg-green-500';
    if (score >= 40) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  // Get color and icon for decision badge
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
          icon: <CheckCircle className="w-5 h-5" />,
          description: 'Safe to proceed'
        };
      case 'WARN':
        return {
          color: 'text-yellow-600',
          bgColor: 'bg-yellow-100',
          icon: <AlertTriangle className="w-5 h-5" />,
          description: 'Proceed with caution'
        };
      case 'BLOCK':
        return {
          color: 'text-red-600',
          bgColor: 'bg-red-100',
          icon: <AlertCircle className="w-5 h-5" />,
          description: 'Access blocked'
        };
      default:
        return {
          color: 'text-gray-600',
          bgColor: 'bg-gray-100',
          icon: <Shield className="w-5 h-5" />,
          description: 'Unknown status'
        };
    }
  };

  const decisionStyle = getDecisionStyle(decision);

  // Prepare risk score gauge data
  const riskGaugeData = [
    { name: 'Risk', value: riskScore, fill: '#ef4444' },
    { name: 'Safe', value: 100 - riskScore, fill: '#e5e7eb' }
  ];

  // Prepare trust gauge data
  const trustGaugeData = [
    { name: 'Trust', value: trustScore, fill: trustScore >= 70 ? '#22c55e' : trustScore >= 40 ? '#eab308' : '#ef4444' },
    { name: 'Distrust', value: 100 - trustScore, fill: '#e5e7eb' }
  ];

  // Detected attacks
  const detectedAttacks = attackIndicators.filter(att => att.detected);
  const severityColors: { [key: string]: string } = {
    critical: 'bg-red-100 text-red-800',
    high: 'bg-orange-100 text-orange-800',
    medium: 'bg-yellow-100 text-yellow-800',
    low: 'bg-blue-100 text-blue-800'
  };

  return (
    <div className="w-full space-y-6 p-4 md:p-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b pb-4">
        <h2 className="text-2xl md:text-3xl font-bold text-gray-900 flex items-center gap-2">
          <Shield className="w-8 h-8" />
          Threat Intelligence Dashboard
        </h2>
      </div>

      {/* Top Row: Decision + Risk & Trust Scores */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Security Decision Card */}
        <Card className="p-6 border-2">
          <div className="flex flex-col items-center justify-center gap-4">
            <div className={`p-4 rounded-full ${decisionStyle.bgColor}`}>
              <div className={`${decisionStyle.color}`}>{decisionStyle.icon}</div>
            </div>
            <div className="text-center">
              <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide">Security Decision</h3>
              <p className={`text-3xl font-bold mt-2 ${decisionStyle.color}`}>{decision}</p>
              <p className="text-xs text-gray-600 mt-2">{decisionStyle.description}</p>
            </div>
            <Badge className={`${decisionStyle.bgColor} ${decisionStyle.color} border-0`}>
              {decision}
            </Badge>
          </div>
        </Card>

        {/* Risk Score Meter */}
        <Card className="p-6 border-2">
          <div className="flex flex-col items-center gap-4">
            <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide w-full text-center">
              Risk Score
            </h3>
            <div className="w-32 h-32">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={riskGaugeData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={65}
                    startAngle={180}
                    endAngle={0}
                    dataKey="value"
                  >
                    {riskGaugeData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.fill} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold text-red-600">{riskScore}</p>
              <p className="text-xs text-gray-600">out of 100</p>
            </div>
          </div>
        </Card>

        {/* Domain Trust Indicator */}
        <Card className="p-6 border-2">
          <div className="flex flex-col items-center gap-4">
            <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide w-full text-center">
              Trust Score
            </h3>
            <div className="w-32 h-32">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={trustGaugeData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={65}
                    startAngle={180}
                    endAngle={0}
                    dataKey="value"
                  >
                    {trustGaugeData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.fill} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="text-center">
              <p className={`text-3xl font-bold ${getTrustColor(trustScore)}`}>{trustScore}</p>
              <p className="text-xs text-gray-600">out of 100</p>
            </div>
          </div>
        </Card>
      </div>

      {/* Middle Row: Attack Indicators */}
      <Card className="p-6 border-2">
        <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <AlertCircle className="w-5 h-5 text-orange-600" />
          Detected Attack Indicators
        </h3>
        
        {detectedAttacks.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {detectedAttacks.map((attack, index) => (
              <div
                key={index}
                className={`p-4 rounded-lg border-2 ${
                  severityColors[attack.severity || 'medium'] || severityColors['medium']
                }`}
              >
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                  <div className="flex-1">
                    <p className="font-semibold capitalize text-sm">{attack.name.replace(/_/g, ' ')}</p>
                    {attack.severity && (
                      <p className="text-xs mt-1 opacity-75 capitalize">{attack.severity} severity</p>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-6 bg-green-50 rounded-lg border border-green-200 text-center">
            <CheckCircle className="w-8 h-8 text-green-600 mx-auto mb-2" />
            <p className="text-green-800 font-medium">No attack indicators detected</p>
          </div>
        )}

        {/* Common Attack Types Reference */}
        {detectedAttacks.length === 0 && (
          <div className="mt-4 pt-4 border-t text-sm text-gray-600">
            <p className="font-medium mb-2">Monitored Threats:</p>
            <ul className="list-disc list-inside space-y-1">
              {attackIndicators.map((att, idx) => (
                <li key={idx} className="text-gray-500">
                  {att.name.replace(/_/g, ' ')}
                </li>
              ))}
            </ul>
          </div>
        )}
      </Card>

      {/* Bottom Row: Explainability Panel */}
      <Card className="p-6 border-2">
        <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <TrendingDown className="w-5 h-5 text-blue-600" />
          Security Analysis
        </h3>

        {/* Summary */}
        <Alert className="mb-4 border-blue-200 bg-blue-50">
          <AlertCircle className="h-4 w-4 text-blue-600" />
          <AlertDescription className="text-gray-800 font-medium">
            {explanation.summary}
          </AlertDescription>
        </Alert>

        {/* Risk Level and Recommended Action */}
        {explanation.risk_level && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div className="p-4 bg-gray-50 rounded-lg border">
              <p className="text-xs font-medium text-gray-600 uppercase">Overall Risk Level</p>
              <p className={`text-2xl font-bold mt-2 ${
                explanation.risk_level === 'CRITICAL' ? 'text-red-600' :
                explanation.risk_level === 'HIGH' ? 'text-orange-600' :
                explanation.risk_level === 'MEDIUM' ? 'text-yellow-600' :
                explanation.risk_level === 'LOW' ? 'text-blue-600' :
                'text-green-600'
              }`}>
                {explanation.risk_level}
              </p>
            </div>
            
            {explanation.recommended_action && (
              <div className="p-4 bg-gray-50 rounded-lg border">
                <p className="text-xs font-medium text-gray-600 uppercase">Recommended Action</p>
                <p className="text-sm font-semibold text-gray-900 mt-2">
                  {explanation.recommended_action}
                </p>
              </div>
            )}
          </div>
        )}

        {/* Detailed Reasons */}
        {explanation.reasons && explanation.reasons.length > 0 && (
          <div>
            <h4 className="text-sm font-semibold text-gray-900 mb-3">Key Findings:</h4>
            <ul className="space-y-2">
              {explanation.reasons.map((reason, index) => (
                <li key={index} className="flex items-start gap-3">
                  <span className="inline-flex items-center justify-center h-6 w-6 rounded-full bg-blue-100 text-blue-600 text-sm font-semibold flex-shrink-0 mt-0.5">
                    {index + 1}
                  </span>
                  <p className="text-gray-700">{reason}</p>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Card>

      {/* Footer with Risk Summary */}
      <div className="p-4 bg-gray-50 rounded-lg border border-gray-200 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="text-sm text-gray-600">
          <p className="font-medium">Scan Summary</p>
          <p className="text-xs mt-1">Overall Risk: <span className="font-semibold">{riskScore > 70 ? 'High' : riskScore > 40 ? 'Medium' : 'Low'}</span> | Trust: <span className="font-semibold">{trustScore > 70 ? 'High' : trustScore > 40 ? 'Medium' : 'Low'}</span> | Decision: <span className="font-semibold">{decision}</span></p>
        </div>
        <div className="text-xs text-gray-500">
          Last scanned: {new Date().toLocaleString()}
        </div>
      </div>
    </div>
  );
};

export default SecurityDashboard;
