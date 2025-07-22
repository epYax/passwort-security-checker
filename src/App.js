import React, { useState, useEffect, useCallback } from 'react';

// Utility functions
const sha1Hash = async (text) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
};

const checkPasswordLeak = async (password) => {
  try {
    const hash = await sha1Hash(password);
    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5);
    
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    const data = await response.text();
    
    const lines = data.split('\n');
    for (const line of lines) {
      const [hashSuffix, count] = line.split(':');
      if (hashSuffix === suffix) {
        return parseInt(count);
      }
    }
    return 0;
  } catch (error) {
    console.error('Leak check error:', error);
    return -1;
  }
};

const generatePassword = (length = 16) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
  let password = '';
  
  // Ensure at least one character from each category
  const categories = [
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ', // uppercase
    'abcdefghijklmnopqrstuvwxyz', // lowercase
    '0123456789', // numbers
    '!@#$%^&*()_+-=[]{}|;:,.<>?' // special chars
  ];
  
  categories.forEach(category => {
    password += category.charAt(Math.floor(Math.random() * category.length));
  });
  
  // Fill remaining length with random chars
  for (let i = password.length; i < length; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  
  // Shuffle the password
  return password.split('').sort(() => Math.random() - 0.5).join('');
};

const calculatePasswordStrength = (password, bsiResults) => {
  if (!password) return 0;
  
  let strength = 0;
  const passedRules = bsiResults.filter(rule => rule.passed).length;
  
  // Base strength from BSI rules (0-60 points)
  strength += (passedRules / bsiResults.length) * 60;
  
  // Length bonus (0-25 points)
  if (password.length >= 8) strength += 10;
  if (password.length >= 12) strength += 10;
  if (password.length >= 16) strength += 5;
  
  // Complexity bonus (0-15 points)
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  
  if (hasLower && hasUpper && hasNumber && hasSpecial) {
    strength += 15;
  }
  
  return Math.min(100, Math.round(strength));
};

// Components
const PasswordInput = ({ password, setPassword, showPassword, setShowPassword }) => {
  return (
    <div className="mb-6">
      <label htmlFor="password" className="block text-sm font-medium mb-2 text-gray-200">
        Passwort eingeben:
      </label>
      <div className="relative">
        <input
          type={showPassword ? "text" : "password"}
          id="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full p-3 pr-12 rounded-md bg-gray-700 border border-gray-600 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          placeholder="Gib dein Passwort ein..."
        />
        <button
          type="button"
          onClick={() => setShowPassword(!showPassword)}
          className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-white transition-colors duration-200"
          aria-label="Passwort anzeigen/verstecken"
        >
          {showPassword ? (
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L3 3m6.878 6.878L21 21"></path>
            </svg>
          ) : (
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
            </svg>
          )}
        </button>
      </div>
    </div>
  );
};

const PasswordStrengthBar = ({ strength }) => {
  const getColor = () => {
    if (strength < 40) return 'bg-red-500';
    if (strength < 70) return 'bg-yellow-500';
    return 'bg-green-500';
  };
  
  const getLabel = () => {
    if (strength < 40) return 'Schwach';
    if (strength < 70) return 'Mittel';
    return 'Stark';
  };

  return (
    <div className="mb-6">
      <div className="flex justify-between items-center mb-2">
        <span className="text-sm font-medium text-gray-200">Passwort-Stärke:</span>
        <span className="text-sm text-gray-300">{getLabel()} ({strength}/100)</span>
      </div>
      <div className="w-full bg-gray-700 rounded-full h-3">
        <div
          className={`h-3 rounded-full transition-all duration-300 ${getColor()}`}
          style={{ width: `${strength}%` }}
        ></div>
      </div>
    </div>
  );
};

const BSICheckList = ({ password }) => {
  const rules = [
    {
      name: 'Mindestens 8 Zeichen (empfohlen 12+)',
      check: password.length >= 8,
      passed: password.length >= 8
    },
    {
      name: 'Enthält Kleinbuchstaben (a-z)',
      check: /[a-z]/.test(password),
      passed: /[a-z]/.test(password)
    },
    {
      name: 'Enthält Großbuchstaben (A-Z)',
      check: /[A-Z]/.test(password),
      passed: /[A-Z]/.test(password)
    },
    {
      name: 'Enthält mindestens 1 Zahl (0-9)',
      check: /[0-9]/.test(password),
      passed: /[0-9]/.test(password)
    },
    {
      name: 'Enthält Sonderzeichen (!@#$%^&*)',
      check: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
      passed: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
    }
  ];

  // Check for simple patterns
  const hasSimplePattern = () => {
    const simple = ['1234', '4321', 'abcd', 'dcba', 'qwerty', 'asdf', 'password', '123456'];
    return simple.some(pattern => password.toLowerCase().includes(pattern));
  };

  const simplePatternRule = {
    name: 'Kein einfaches Muster (1234, qwerty, etc.)',
    check: !hasSimplePattern(),
    passed: !hasSimplePattern()
  };

  const allRules = [...rules, simplePatternRule];

  return (
    <div className="mb-6 p-4 bg-gray-700 rounded-md">
      <h3 className="font-semibold mb-3 text-gray-200">📋 BSI-Sicherheitsregeln:</h3>
      <ul className="space-y-2">
        {allRules.map((rule, index) => (
          <li key={index} className="flex items-center">
            <span className="mr-2">
              {rule.passed ? '✅' : '❌'}
            </span>
            <span className={rule.passed ? 'text-green-400' : 'text-red-400'}>
              {rule.name}
            </span>
          </li>
        ))}
      </ul>
      {allRules.filter(rule => rule.passed).length < allRules.length && (
        <p className="text-sm text-yellow-300 mt-3 italic">
          💡 Tipp: Verwende 12+ Zeichen und verschiedene Zeichenarten für mehr Sicherheit.
        </p>
      )}
    </div>
  );
};

const PasswordGenerator = ({ onPasswordGenerated }) => {
  const [generatedPassword, setGeneratedPassword] = useState('');
  const [passwordLength, setPasswordLength] = useState(16);
  const [copied, setCopied] = useState(false);

  const handleGenerate = () => {
    const newPassword = generatePassword(passwordLength);
    setGeneratedPassword(newPassword);
    onPasswordGenerated(newPassword);
  };

  const handleCopy = async () => {
    if (generatedPassword) {
      await navigator.clipboard.writeText(generatedPassword);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="mb-6 p-4 bg-gray-700 rounded-md">
      <h3 className="font-semibold mb-3 text-gray-200">🎲 Passwort-Generator:</h3>
      <div className="flex items-center space-x-4 mb-3">
        <label className="text-sm text-gray-300">
          Länge:
          <input
            type="number"
            min="8"
            max="50"
            value={passwordLength}
            onChange={(e) => setPasswordLength(parseInt(e.target.value))}
            className="ml-2 w-16 p-1 bg-gray-600 text-white rounded text-center"
          />
        </label>
        <button
          onClick={handleGenerate}
          className="bg-green-600 text-white px-4 py-2 rounded hover:bg-green-700 transition-colors duration-200"
        >
          Generieren
        </button>
      </div>
      {generatedPassword && (
        <div className="flex items-center space-x-2">
          <input
            type="text"
            value={generatedPassword}
            readOnly
            className="flex-1 p-2 bg-gray-600 text-white rounded font-mono text-sm"
          />
          <button
            onClick={handleCopy}
            className={`px-3 py-2 rounded transition-colors duration-200 ${
              copied ? 'bg-green-600' : 'bg-blue-600 hover:bg-blue-700'
            } text-white`}
          >
            {copied ? '✓' : 'Kopieren'}
          </button>
        </div>
      )}
    </div>
  );
};

const ResultPanel = ({ password, onCheckLeak }) => {
  const [leakData, setLeakData] = useState(null);
  const [isChecking, setIsChecking] = useState(false);

  const handleLeakCheck = async () => {
    if (!password) return;
    
    setIsChecking(true);
    try {
      const leakCount = await checkPasswordLeak(password);
      setLeakData(leakCount);
    } finally {
      setIsChecking(false);
    }
  };

  useEffect(() => {
    if (!password) {
      setLeakData(null);
    }
  }, [password]);

  return (
    <div className="mb-6">
      <div className="flex items-center space-x-4 mb-4">
        <button
          onClick={handleLeakCheck}
          disabled={!password || isChecking}
          className="bg-blue-600 text-white px-6 py-2 rounded hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors duration-200"
        >
          {isChecking ? 'Prüfe...' : 'Leak-Check starten'}
        </button>
        {isChecking && (
          <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-500"></div>
        )}
      </div>
      
      {leakData !== null && (
        <div className={`p-4 rounded-md ${
          leakData === -1 ? 'bg-yellow-600' : 
          leakData > 0 ? 'bg-red-600' : 'bg-green-600'
        }`}>
          <h3 className="font-semibold mb-2">🌐 HaveIBeenPwned Check:</h3>
          {leakData === -1 ? (
            <p>⚠️ Fehler beim Prüfen der Leak-Datenbank. Versuche es später erneut.</p>
          ) : leakData > 0 ? (
            <div>
              <p><strong>⚠️ Dein Passwort wurde {leakData.toLocaleString()}-mal geleakt!</strong></p>
              <p className="text-sm mt-1">Du solltest dieses Passwort sofort ändern.</p>
            </div>
          ) : (
            <p><strong>✅ Dein Passwort wurde nicht in der Leak-Datenbank gefunden.</strong></p>
          )}
        </div>
      )}
    </div>
  );
};

// Main App Component
const App = () => {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  
  // Calculate BSI results for strength calculation
  const getBSIResults = useCallback((pwd) => {
    const rules = [
      { name: 'length', passed: pwd.length >= 8 },
      { name: 'lowercase', passed: /[a-z]/.test(pwd) },
      { name: 'uppercase', passed: /[A-Z]/.test(pwd) },
      { name: 'numbers', passed: /[0-9]/.test(pwd) },
      { name: 'special', passed: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pwd) },
      { name: 'pattern', passed: !['1234', '4321', 'abcd', 'dcba', 'qwerty', 'asdf', 'password', '123456'].some(pattern => pwd.toLowerCase().includes(pattern)) }
    ];
    return rules;
  }, []);
  
  const bsiResults = getBSIResults(password);
  const strength = calculatePasswordStrength(password, bsiResults);

  const handleGeneratedPassword = (newPassword) => {
    setPassword(newPassword);
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center p-4">
      <div className="bg-gray-800 p-8 rounded-lg shadow-xl max-w-2xl w-full">
        <h1 className="text-3xl font-bold text-center mb-2">🔒 Password Security Checker</h1>
        <p className="text-gray-300 text-center mb-8">
          Prüfe die Sicherheit deines Passworts mit BSI-Richtlinien und Leak-Detection
        </p>

        <PasswordInput 
          password={password} 
          setPassword={setPassword}
          showPassword={showPassword}
          setShowPassword={setShowPassword}
        />
        
        <PasswordStrengthBar strength={strength} />
        
        <BSICheckList password={password} />
        
        <PasswordGenerator onPasswordGenerated={handleGeneratedPassword} />
        
        <ResultPanel password={password} />
        
        {password && (
          <div className="text-center text-sm text-gray-400">
            <p>🔐 Alle Berechnungen erfolgen lokal in deinem Browser.</p>
            <p>Dein Passwort wird niemals gespeichert oder übertragen.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default App;