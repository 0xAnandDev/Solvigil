import React, { useState, useRef } from 'react';
import { createRoot } from 'react-dom/client';

const ScannerApp = () => {
  const [file, setFile] = useState(null);
  const [isDragActive, setIsDragActive] = useState(false);
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisComplete, setAnalysisComplete] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  
  const fileInputRef = useRef(null);

  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const validateAndSetFile = (uploadedFile) => {
    if (uploadedFile && uploadedFile.name.endsWith('.sol')) {
      setFile(uploadedFile);
      // Reset state if a new file is uploaded
      setAnalysisComplete(false);
      setAnalysisResult(null);
    } else {
      alert("Please upload a valid Solidity (.sol) file.");
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const handleRemoveFile = () => {
    setFile(null);
    setAnalysisComplete(false);
    setAnalysisResult(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleAnalyze = () => {
    if (!file || !termsAccepted) return;
    
    setIsAnalyzing(true);
    
    // Simulate analysis delay
    setTimeout(() => {
      setAnalysisResult({
        score: 78,
        issues: {
          high: 2,
          medium: 4,
          low: 11
        }
      });
      setIsAnalyzing(false);
      setAnalysisComplete(true);
    }, 2500);
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="min-h-screen flex flex-col font-body bg-[#E4DDD3] text-gray-900 selection:bg-[#00A19B] selection:text-white">
      {/* Top Left Logo */}
      <header className="p-6 md:p-8">
        <a href="/" className="flex items-center gap-3 w-max group">
          <div className="w-10 h-10 rounded-xl bg-[#00A19B] flex items-center justify-center text-white shadow-lg shadow-[#00A19B]/20 group-hover:scale-105 transition-transform">
            <svg xmlns="http://www.w3.org/2000/svg" className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="m9 12 2 2 4-4"/>
            </svg>
          </div>
          <span className="font-logo font-bold text-2xl tracking-tight text-gray-900 lowercase" style={{ letterSpacing: "-0.02em" }}>solvigil</span>
        </a>
      </header>

      {/* Main Content */}
      <main className="flex-1 flex flex-col items-center justify-center p-4 sm:p-6 w-full max-w-2xl mx-auto mb-20">
        
        {/* Container Card */}
        <div className="w-full bg-white/60 backdrop-blur-md rounded-3xl p-8 shadow-xl shadow-black/5 border border-white/50">
          
          <div className="text-center mb-8">
            <h1 className="text-2xl sm:text-3xl font-bold font-heading mb-2 text-gray-900">Scan Your Contract</h1>
            <p className="text-gray-600 text-sm sm:text-base">Upload your Solidity file for a comprehensive security analysis.</p>
          </div>

          {!file ? (
            /* Upload Area */
            <div 
              className={`w-full relative rounded-2xl border-2 border-dashed transition-all duration-300 ease-in-out p-10 flex flex-col items-center justify-center cursor-pointer ${
                isDragActive 
                  ? 'border-[#00A19B] bg-[#00A19B]/5 scale-[1.02]' 
                  : 'border-[#00A19B]/40 hover:border-[#00A19B] hover:bg-white/50'
              }`}
              onDragEnter={handleDragEnter}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current.click()}
            >
              <input 
                type="file" 
                ref={fileInputRef} 
                onChange={handleFileSelect} 
                accept=".sol" 
                className="hidden" 
              />
              
              <div className="w-16 h-16 mb-4 rounded-full bg-[#00A19B]/10 flex items-center justify-center text-[#00A19B]">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
              </div>
              <p className="font-semibold text-lg text-gray-800 mb-1">Drop your .sol file here</p>
              <p className="text-gray-500 text-sm">or click to upload</p>
            </div>
          ) : (
            /* File Info Area */
            <div className="w-full bg-white rounded-2xl p-6 border border-gray-100 shadow-sm flex items-center justify-between mb-6">
              <div className="flex items-center gap-4 overflow-hidden">
                <div className="w-12 h-12 rounded-xl bg-[#00A19B]/10 flex-shrink-0 flex items-center justify-center text-[#00A19B]">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                </div>
                <div className="overflow-hidden">
                  <h3 className="font-semibold text-gray-900 truncate">{file.name}</h3>
                  <p className="text-gray-500 text-sm">{formatFileSize(file.size)}</p>
                </div>
              </div>
              {!isAnalyzing && !analysisComplete && (
                <button 
                  onClick={handleRemoveFile}
                  className="p-2 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors"
                  aria-label="Remove file"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
              )}
            </div>
          )}

          {/* Trust Indicators */}
          <div className="flex flex-wrap items-center justify-center gap-4 sm:gap-8 mt-6 mb-8 text-sm text-gray-600">
            <div className="flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 text-[#00A19B]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              <span>Secure local analysis</span>
            </div>
            <div className="flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 text-[#00A19B]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              <span>No gas fees</span>
            </div>
            <div className="flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 text-[#00A19B]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
              </svg>
              <span>No wallet required</span>
            </div>
          </div>

          {/* Terms and Analyze Button */}
          {!analysisComplete && (
            <div className="flex flex-col items-center gap-6 border-t border-gray-200/60 pt-6">
              <label className="flex items-center gap-3 cursor-pointer group">
                <div className="relative flex items-center justify-center">
                  <input 
                    type="checkbox" 
                    className="peer sr-only"
                    checked={termsAccepted}
                    onChange={(e) => setTermsAccepted(e.target.checked)}
                    disabled={isAnalyzing}
                  />
                  <div className={`w-5 h-5 rounded border flex items-center justify-center transition-colors ${
                    termsAccepted 
                      ? 'bg-[#00A19B] border-[#00A19B]' 
                      : 'border-gray-300 bg-white group-hover:border-[#00A19B]'
                  }`}>
                    {termsAccepted && (
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 text-white" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                      </svg>
                    )}
                  </div>
                </div>
                <span className="text-gray-600 text-sm">I agree to the terms and conditions</span>
              </label>

              <button 
                onClick={handleAnalyze}
                disabled={!file || !termsAccepted || isAnalyzing}
                className={`w-full sm:w-auto px-10 h-14 rounded-full font-semibold text-lg transition-all duration-300 flex items-center justify-center gap-3 ${
                  !file || !termsAccepted || isAnalyzing
                    ? 'bg-gray-200 text-gray-400 cursor-not-allowed'
                    : 'bg-[#00A19B] text-white hover:bg-[#008680] hover:-translate-y-1 shadow-xl shadow-[#00A19B]/25'
                }`}
              >
                {isAnalyzing ? (
                  <>
                    <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Analyzing smart contract...
                  </>
                ) : (
                  'Analyze Contract'
                )}
              </button>
            </div>
          )}

          {/* Analysis Results Summary */}
          {analysisComplete && analysisResult && (
            <div className="border-t border-gray-200/60 pt-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
              <div className="bg-white rounded-2xl p-6 border border-gray-100 shadow-sm flex flex-col sm:flex-row items-center justify-between gap-6 mb-8">
                
                <div className="flex items-center gap-5">
                  <div className="relative w-16 h-16 flex items-center justify-center">
                    <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                      <path
                        className="text-gray-100"
                        strokeWidth="3"
                        stroke="currentColor"
                        fill="none"
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                      />
                      <path
                        className={analysisResult.score >= 70 ? "text-[#00A19B]" : analysisResult.score >= 40 ? "text-yellow-500" : "text-red-500"}
                        strokeDasharray={`${analysisResult.score}, 100`}
                        strokeWidth="3"
                        strokeLinecap="round"
                        stroke="currentColor"
                        fill="none"
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                      />
                    </svg>
                    <div className="absolute inset-0 flex items-center justify-center flex-col">
                      <span className="text-xl font-bold font-heading text-gray-900">{analysisResult.score}</span>
                    </div>
                  </div>
                  <div>
                    <p className="text-sm text-gray-500 uppercase tracking-wide font-semibold mb-1">Security Score</p>
                    <p className="text-gray-900 font-medium text-lg">
                      {analysisResult.score >= 80 ? 'Good' : analysisResult.score >= 50 ? 'Fair' : 'Poor'} Status
                    </p>
                  </div>
                </div>

                <div className="flex gap-4">
                  <div className="text-center px-4">
                    <p className="text-2xl font-bold text-red-500">{analysisResult.issues.high}</p>
                    <p className="text-xs text-gray-500 uppercase font-semibold">High</p>
                  </div>
                  <div className="w-px bg-gray-200"></div>
                  <div className="text-center px-4">
                    <p className="text-2xl font-bold text-yellow-500">{analysisResult.issues.medium}</p>
                    <p className="text-xs text-gray-500 uppercase font-semibold">Med</p>
                  </div>
                  <div className="w-px bg-gray-200"></div>
                  <div className="text-center px-4">
                    <p className="text-2xl font-bold text-blue-500">{analysisResult.issues.low}</p>
                    <p className="text-xs text-gray-500 uppercase font-semibold">Low</p>
                  </div>
                </div>
                
              </div>

              <div className="flex justify-center">
                <a 
                  href="/report.html" 
                  className="bg-gray-900 text-white px-10 h-14 rounded-full font-semibold text-lg hover:bg-black hover:-translate-y-1 transition-all duration-300 shadow-xl shadow-black/20 flex items-center gap-2"
                >
                  View Full Report
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M12.293 5.293a1 1 0 011.414 0l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-2.293-2.293a1 1 0 010-1.414z" clipRule="evenodd" />
                  </svg>
                </a>
              </div>
            </div>
          )}

        </div>
      </main>
    </div>
  );
};

const root = createRoot(document.getElementById('root'));
root.render(<ScannerApp />);
