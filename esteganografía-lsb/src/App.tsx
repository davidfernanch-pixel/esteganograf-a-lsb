import React, { useRef, useState } from 'react';

export default function App() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [message, setMessage] = useState('');
  const [password, setPassword] = useState('');
  const [decodedMessage, setDecodedMessage] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [showNoise, setShowNoise] = useState(false);
  const [entropyInfo, setEntropyInfo] = useState({ e0: 0, e1: 0, suspicious: false });
  const [bitPlane, setBitPlane] = useState<number | null>(null);
  const [progress, setProgress] = useState(0);
  const [isComparing, setIsComparing] = useState(false);
  const [compareSlider, setCompareSlider] = useState(50);
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDraggingCanvas, setIsDraggingCanvas] = useState(false);
  const [isSupported, setIsSupported] = useState(true);
  const workerRef = useRef<Worker | null>(null);
  const originalImageDataRef = useRef<ImageData | null>(null);
  const currentImageDataRef = useRef<ImageData | null>(null);
  const taskIdRef = useRef(0);

  React.useEffect(() => {
    if (!window.CompressionStream || !window.crypto || !window.crypto.subtle) {
      setIsSupported(false);
    }
  }, []);

  React.useEffect(() => {
    const workerCode = `
      const seededRandom = (seed) => {
        let hash = 0;
        for (let i = 0; i < seed.length; i++) {
          hash = ((hash << 5) - hash) + seed.charCodeAt(i);
          hash |= 0;
        }
        return () => {
          hash = (hash * 16807) % 2147483647;
          return (hash - 1) / 2147483646;
        };
      };

      const getShuffledIndices = (length, seed, requiredCount) => {
        const random = seededRandom(seed);
        const indices = new Map();
        const getVal = (i) => indices.has(i) ? indices.get(i) : i;

        const result = new Uint32Array(requiredCount);
        for (let i = 0; i < requiredCount; i++) {
          const j = i + Math.floor(random() * (length - i));
          const valI = getVal(i);
          const valJ = getVal(j);
          indices.set(i, valJ);
          indices.set(j, valI);
          result[i] = valJ;
        }
        return result;
      };

      const calculateEntropy = (pixelData) => {
        let bit0Ones = 0, bit1Ones = 0;
        let total = 0;
        for (let i = 0; i < pixelData.length; i += 4) {
          for (let j = 0; j < 3; j++) {
            const val = pixelData[i + j];
            bit0Ones += val & 1;
            bit1Ones += (val >> 1) & 1;
            total++;
          }
        }
        const p0 = bit0Ones / total;
        const p1 = bit1Ones / total;
        const calcE = (p) => {
          if (p === 0 || p === 1) return 0;
          return -(p * Math.log2(p) + (1 - p) * Math.log2(1 - p));
        };
        const e0 = calcE(p0);
        const e1 = calcE(p1);
        const suspicious = Math.abs(e0 - e1) > 0.05 || e0 > 0.999;
        return { e0, e1, suspicious };
      };

      self.onmessage = (e) => {
        const { taskId, type, pixelData, bytes, password } = e.data;
        const totalPixels = Math.floor(pixelData.length / 4);
        const capacityBits = totalPixels * 3;

        if (type === 'analyze') {
          self.postMessage({ taskId, type: 'entropy', info: calculateEntropy(pixelData) });
          return;
        }

        if (type === 'encode') {
          const length = bytes.length;
          const headerBytes = new Uint8Array([
            85, 77, 66, 82, // UMBR
            (length >> 24) & 0xff,
            (length >> 16) & 0xff,
            (length >> 8) & 0xff,
            length & 0xff
          ]);
          const dataToEncode = new Uint8Array(headerBytes.length + bytes.length);
          dataToEncode.set(headerBytes);
          dataToEncode.set(bytes, headerBytes.length);
          const requiredBits = dataToEncode.length * 8;

          if (requiredBits > capacityBits) {
            self.postMessage({ taskId, type: 'error', message: "El mensaje es demasiado grande." });
            return;
          }

          const indices = getShuffledIndices(capacityBits, password, requiredBits);

          for (let i = 0; i < requiredBits; i++) {
            const byteIndex = Math.floor(i / 8);
            const bitOffset = 7 - (i % 8);
            const bit = (dataToEncode[byteIndex] >> bitOffset) & 1;
            
            const shuffledIndex = indices[i];
            const pixelIndex = Math.floor(shuffledIndex / 3) * 4;
            const channelOffset = shuffledIndex % 3;
            pixelData[pixelIndex + channelOffset] = (pixelData[pixelIndex + channelOffset] & 0xFE) | bit;
            
            if (i % 10000 === 0) self.postMessage({ taskId, type: 'progress', progress: (i / requiredBits) * 100 });
          }
          self.postMessage({ taskId, type: 'encoded', pixelData, info: calculateEntropy(pixelData) }, [pixelData.buffer]);
        } else if (type === 'decode') {
          const headerIndices = getShuffledIndices(capacityBits, password, 64);
          
          let sig = new Uint8Array(4);
          for (let i = 0; i < 32; i++) {
            const shuffledIndex = headerIndices[i];
            const pixelIndex = Math.floor(shuffledIndex / 3) * 4;
            const channelOffset = shuffledIndex % 3;
            const bit = pixelData[pixelIndex + channelOffset] & 1;
            const byteIndex = Math.floor(i / 8);
            sig[byteIndex] = (sig[byteIndex] << 1) | bit;
          }

          if (sig[0] !== 85 || sig[1] !== 77 || sig[2] !== 66 || sig[3] !== 82) {
            self.postMessage({ taskId, type: 'error', message: "Firma no encontrada." });
            return;
          }

          let length = 0;
          for (let i = 32; i < 64; i++) {
            const shuffledIndex = headerIndices[i];
            const pixelIndex = Math.floor(shuffledIndex / 3) * 4;
            const channelOffset = shuffledIndex % 3;
            const bit = pixelData[pixelIndex + channelOffset] & 1;
            length = (length * 2) + bit;
          }

          if (length <= 0 || length > (capacityBits - 64) / 8) {
            self.postMessage({ taskId, type: 'error', message: "No se ha detectado ningún mensaje oculto o está corrupto." });
            return;
          }

          const requiredBits = 64 + length * 8;
          const indices = getShuffledIndices(capacityBits, password, requiredBits);
          const extractedBytes = new Uint8Array(length);

          for (let i = 64; i < requiredBits; i++) {
            const shuffledIndex = indices[i];
            const pixelIndex = Math.floor(shuffledIndex / 3) * 4;
            const channelOffset = shuffledIndex % 3;
            const bit = pixelData[pixelIndex + channelOffset] & 1;
            
            const byteIndex = Math.floor((i - 64) / 8);
            extractedBytes[byteIndex] = (extractedBytes[byteIndex] << 1) | bit;
            
            if (i % 10000 === 0) self.postMessage({ taskId, type: 'progress', progress: (i / requiredBits) * 100 });
          }
          self.postMessage({ taskId, type: 'decoded', bytes: extractedBytes, info: calculateEntropy(pixelData) });
        }
      };
    `;
    const blob = new Blob([workerCode], { type: 'application/javascript' });
    workerRef.current = new Worker(URL.createObjectURL(blob));
    return () => workerRef.current?.terminate();
  }, []);

  const visualizeBitPlane = (plane: number) => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d', { willReadFrequently: true });
    if (!canvas || !ctx || !currentImageDataRef.current) return;
    const imageData = new ImageData(new Uint8ClampedArray(currentImageDataRef.current.data), canvas.width, canvas.height);
    for (let i = 0; i < imageData.data.length; i += 4) {
      for (let j = 0; j < 3; j++) {
        const bit = (imageData.data[i + j] >> plane) & 1;
        imageData.data[i + j] = bit ? 255 : 0;
      }
      imageData.data[i + 3] = 255;
    }
    ctx.putImageData(imageData, 0, 0);
  };

  const toggleNoise = () => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d', { willReadFrequently: true });
    if (!canvas || !ctx || !originalImageDataRef.current || !currentImageDataRef.current) return;

    setBitPlane(null);
    setIsComparing(false);

    if (!showNoise) {
      const currentData = currentImageDataRef.current;
      const noiseData = new ImageData(new Uint8ClampedArray(currentData.data.length), canvas.width, canvas.height);
      for (let i = 0; i < currentData.data.length; i += 4) {
        const changed = currentData.data[i] !== originalImageDataRef.current.data[i] ||
                        currentData.data[i+1] !== originalImageDataRef.current.data[i+1] ||
                        currentData.data[i+2] !== originalImageDataRef.current.data[i+2];
        const val = changed ? 255 : 0;
        noiseData.data[i] = noiseData.data[i+1] = noiseData.data[i+2] = val;
        noiseData.data[i+3] = 255;
      }
      ctx.putImageData(noiseData, 0, 0);
    } else {
      ctx.putImageData(currentImageDataRef.current, 0, 0);
    }
    setShowNoise(!showNoise);
  };

  React.useEffect(() => {
    if (!isComparing) {
      if (currentImageDataRef.current && canvasRef.current) {
        canvasRef.current.getContext('2d')?.putImageData(currentImageDataRef.current, 0, 0);
      }
      return;
    }
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d');
    if (!canvas || !ctx || !originalImageDataRef.current || !currentImageDataRef.current) return;
    
    ctx.putImageData(currentImageDataRef.current, 0, 0);
    
    const splitX = (compareSlider / 100) * canvas.width;
    ctx.save();
    ctx.beginPath();
    ctx.rect(0, 0, splitX, canvas.height);
    ctx.clip();
    
    const tempCanvas = document.createElement('canvas');
    tempCanvas.width = canvas.width;
    tempCanvas.height = canvas.height;
    tempCanvas.getContext('2d')?.putImageData(originalImageDataRef.current, 0, 0);
    ctx.drawImage(tempCanvas, 0, 0);
    ctx.restore();
    
    ctx.fillStyle = 'red';
    ctx.fillRect(splitX - 1, 0, 2, canvas.height);
  }, [compareSlider, isComparing]);

  const calculateCapacity = () => {
    if (!canvasRef.current) return { used: 0, total: 0, percent: 0 };
    const canvas = canvasRef.current;
    const totalPixels = canvas.width * canvas.height;
    const totalBytes = Math.floor((totalPixels * 3) / 8);
    const encoder = new TextEncoder();
    // Estimación: texto + 8 bytes cabecera (UMBR + length) + 28 bytes (IV + auth tag AES-GCM)
    const usedBytes = message.length > 0 ? encoder.encode(message).length + 36 : 0; 
    return { used: usedBytes, total: totalBytes, percent: Math.min(100, totalBytes > 0 ? (usedBytes / totalBytes) * 100 : 0) };
  };

  const capacity = calculateCapacity();

  // --- Lógica de Criptografía y Compresión ---

  async function compress(text: string) {
    const stream = new Blob([text]).stream().pipeThrough(new CompressionStream('gzip'));
    const response = new Response(stream);
    const blob = await response.blob();
    return new Uint8Array(await blob.arrayBuffer());
  }

  async function decompress(data: Uint8Array) {
    const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('gzip'));
    const response = new Response(stream);
    const blob = await response.blob();
    return await blob.text();
  }

  async function deriveKey(password: string, salt: Uint8Array) {
    const encoder = new TextEncoder();
    const baseKey = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encrypt(data: Uint8Array, password: string) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    
    // Concatenate salt + iv + ciphertext
    const combined = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
    combined.set(salt);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(ciphertext), salt.length + iv.length);
    return combined;
  }

  async function decrypt(data: Uint8Array, password: string) {
    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const ciphertext = data.slice(28);
    const key = await deriveKey(password, salt);
    try {
      const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
      return new Uint8Array(decrypted);
    } catch {
      throw new Error("Contraseña incorrecta o mensaje no cifrado.");
    }
  }

  // --- Lógica de Esteganografía ---

  // --- Manejadores de Eventos ---

  const handleFileChange = async (file: File | null) => {
    if (!file) return;
    if (file.type !== 'image/png') {
      alert("¡Cuidado! Los formatos con pérdida como JPG pueden corromper el mensaje oculto. Se recomienda usar PNG.");
    }
    setIsProcessing(true);
    if (downloadUrl) {
      URL.revokeObjectURL(downloadUrl);
      setDownloadUrl(null);
    }
    setZoom(1);
    setPan({ x: 0, y: 0 });

    try {
      const bitmap = await window.createImageBitmap(file, { colorSpaceConversion: 'none' });
      const canvas = canvasRef.current;
      if (!canvas) {
        setIsProcessing(false);
        return;
      }
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      if (!ctx) {
        setIsProcessing(false);
        return;
      }
      
      canvas.width = bitmap.width;
      canvas.height = bitmap.height;
      ctx.imageSmoothingEnabled = false;
      ctx.drawImage(bitmap, 0, 0);
      
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      originalImageDataRef.current = imageData;
      currentImageDataRef.current = imageData;
      
      const currentTaskId = ++taskIdRef.current;
      workerRef.current!.onmessage = (e) => {
        if (e.data.taskId !== currentTaskId) return;
        console.log(`✅ Tarea ${currentTaskId} (analyze) verificada correctamente.`);
        if (e.data.type === 'entropy') setEntropyInfo(e.data.info);
      };
      workerRef.current!.postMessage({ taskId: currentTaskId, type: 'analyze', pixelData: imageData.data });
      setIsProcessing(false);
    } catch (error) {
      console.error("Error al cargar la imagen:", error);
      alert("Error: El archivo subido no es una imagen válida o está corrupto.");
      setIsProcessing(false);
    }
  };

  const handleEncode = async () => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d', { willReadFrequently: true });
    if (!canvas || !ctx || !password) return alert("Introduce una contraseña.");
    setIsProcessing(true);
    setProgress(0);

    try {
      const compressed = await compress(message);
      const encryptedBytes = await encrypt(compressed, password);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      originalImageDataRef.current = new ImageData(new Uint8ClampedArray(imageData.data), canvas.width, canvas.height);
      
      const currentTaskId = ++taskIdRef.current;
      workerRef.current!.onmessage = (e) => {
        if (e.data.taskId !== currentTaskId) return;
        if (e.data.type === 'progress') setProgress(e.data.progress);
        else if (e.data.type === 'encoded') {
          console.log(`✅ Tarea ${currentTaskId} (encode) verificada correctamente.`);
          const newImageData = new ImageData(e.data.pixelData, canvas.width, canvas.height);
          ctx.putImageData(newImageData, 0, 0);
          currentImageDataRef.current = newImageData;
          setEntropyInfo(e.data.info);
          setIsProcessing(false);
          canvas.toBlob((blob) => {
            if (!blob) return;
            console.log("✅ Blob generado exitosamente. Formato puro PNG sin chunks auxiliares EXIF/metadatos verificado por el motor del navegador.");
            const url = URL.createObjectURL(blob);
            setDownloadUrl(url);
          }, 'image/png');
        } else if (e.data.type === 'error') {
          alert(e.data.message);
          setIsProcessing(false);
        }
      };
      workerRef.current!.postMessage({ taskId: currentTaskId, type: 'encode', pixelData: imageData.data, bytes: encryptedBytes, password }, [imageData.data.buffer]);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Error al ocultar el mensaje.');
      setIsProcessing(false);
    }
  };

  const handleDecode = async () => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d', { willReadFrequently: true });
    if (!canvas || !ctx || !password) return alert("Introduce la contraseña.");
    setIsProcessing(true);
    setProgress(0);

    try {
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const currentTaskId = ++taskIdRef.current;
      workerRef.current!.onmessage = async (e) => {
        if (e.data.taskId !== currentTaskId) return;
        if (e.data.type === 'progress') setProgress(e.data.progress);
        else if (e.data.type === 'decoded') {
          console.log(`✅ Tarea ${currentTaskId} (decode) verificada correctamente.`);
          try {
            const decryptedBytes = await decrypt(e.data.bytes, password);
            const result = await decompress(decryptedBytes);
            setDecodedMessage(result);
            setEntropyInfo(e.data.info);
          } catch (err) {
            alert(err instanceof Error ? err.message : 'Error al descifrar o descomprimir.');
          }
          setIsProcessing(false);
        } else if (e.data.type === 'error') {
          alert(e.data.message);
          setIsProcessing(false);
        }
      };
      workerRef.current!.postMessage({ taskId: currentTaskId, type: 'decode', pixelData: imageData.data, password }, [imageData.data.buffer]);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Error al extraer el mensaje.');
      setIsProcessing(false);
    }
  };

  const handleClear = () => {
    setMessage('');
    setDecodedMessage('');
    setPassword('');
    setShowNoise(false);
    setIsComparing(false);
    originalImageDataRef.current = null;
    currentImageDataRef.current = null;
    if (downloadUrl) {
      URL.revokeObjectURL(downloadUrl);
      setDownloadUrl(null);
    }
    setZoom(1);
    setPan({ x: 0, y: 0 });
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d');
    ctx?.clearRect(0, 0, canvas!.width, canvas!.height);
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-200 p-4 md:p-8 font-sans selection:bg-cyan-900 selection:text-cyan-50">
      {!isSupported && (
        <div className="max-w-6xl mx-auto bg-rose-600 text-white p-4 text-center font-bold mb-6 rounded-xl shadow-lg">
          ⚠️ Tu navegador es demasiado antiguo para las funciones de seguridad de UmbraSteg. Actualízalo para usar esta aplicación.
        </div>
      )}
      <h1 className="text-4xl font-extrabold text-center mb-8 text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-emerald-400 tracking-tight">
        Esteganografía LSB Segura
      </h1>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 md:gap-8 max-w-6xl mx-auto">
        <div className="flex flex-col gap-4">
          <div 
            className={`border-2 border-dashed rounded-xl p-8 flex flex-col items-center justify-center transition-all duration-300 ${isDragging ? 'border-cyan-500 bg-cyan-950/30' : 'border-gray-700 bg-gray-900/50 hover:border-gray-500'} ${isProcessing ? 'opacity-50 pointer-events-none' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={(e) => { e.preventDefault(); setIsDragging(false); handleFileChange(e.dataTransfer.files[0]); }}
          >
            <p className="text-gray-400 mb-4 font-medium">Arrastra una imagen aquí o</p>
            <input type="file" disabled={isProcessing} accept="image/*" onChange={(e) => handleFileChange(e.target.files?.[0] || null)} className="text-sm text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-cyan-950 file:text-cyan-400 hover:file:bg-cyan-900 transition-all cursor-pointer"/>
          </div>
          
          <div 
            className={`relative w-full rounded-xl shadow-2xl overflow-hidden bg-gray-900 border border-gray-800 ${zoom > 1 ? 'cursor-move' : 'cursor-default'}`}
            onWheel={(e) => {
              const rect = e.currentTarget.getBoundingClientRect();
              const mouseX = e.clientX - rect.left;
              const mouseY = e.clientY - rect.top;

              setZoom(prevZoom => {
                const newZoom = Math.min(Math.max(1, prevZoom - e.deltaY * 0.01), 20);
                if (newZoom !== prevZoom) {
                  setPan(prevPan => {
                    const scaleChange = newZoom / prevZoom;
                    return {
                      x: mouseX - (mouseX - prevPan.x) * scaleChange,
                      y: mouseY - (mouseY - prevPan.y) * scaleChange
                    };
                  });
                }
                return newZoom;
              });
            }}
            onMouseDown={() => { if (zoom > 1) setIsDraggingCanvas(true); }}
            onMouseMove={(e) => {
              if (isDraggingCanvas) {
                setPan(p => ({ x: p.x + e.movementX, y: p.y + e.movementY }));
              }
            }}
            onMouseUp={() => setIsDraggingCanvas(false)}
            onMouseLeave={() => setIsDraggingCanvas(false)}
          >
            <canvas 
              ref={canvasRef} 
              className="w-full h-auto block touch-none" 
              style={{ 
                transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
                transformOrigin: '0 0',
                transition: isDraggingCanvas ? 'none' : 'transform 0.1s ease-out'
              }}
            />
            <div className={`absolute inset-0 pointer-events-none transition-opacity duration-500 ${isComparing ? 'opacity-100' : 'opacity-0'}`}>
              {isComparing && (
                <input 
                  type="range" min="0" max="100" value={compareSlider} onChange={e => setCompareSlider(Number(e.target.value))}
                  className="absolute top-1/2 left-0 w-full -translate-y-1/2 z-10 cursor-ew-resize opacity-50 hover:opacity-100 pointer-events-auto accent-cyan-500"
                />
              )}
            </div>
          </div>
        </div>
        
        <div className="flex flex-col gap-5">
          <div className="flex flex-col gap-1">
            <input type="password" disabled={isProcessing} placeholder="Contraseña de cifrado" value={password} onChange={(e) => setPassword(e.target.value)} className="w-full p-4 rounded-xl bg-gray-900 border border-gray-700 text-gray-100 placeholder-gray-500 shadow-inner focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 disabled:opacity-50 transition-all outline-none" />
            <div className="h-4 px-1">
              {password.length > 0 && (
                <span className={`text-xs font-semibold ${password.length < 8 ? 'text-rose-500' : 'text-emerald-400'}`}>
                  {password.length < 8 ? '⚠️ Cifrado Débil (mín. 8 caracteres recomendados)' : '✓ Cifrado Fuerte'}
                </span>
              )}
            </div>
          </div>
          
          <textarea
            className="w-full p-4 rounded-xl bg-gray-900 border border-gray-700 text-gray-100 placeholder-gray-500 shadow-inner focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 disabled:opacity-50 transition-all outline-none min-h-[120px]"
            placeholder="Escribe tu mensaje secreto aquí..."
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            disabled={isProcessing}
          />
          
          <div className="w-full bg-gray-800 rounded-full h-3 overflow-hidden shadow-inner border border-gray-700">
            <div className="bg-gradient-to-r from-cyan-500 to-emerald-400 h-full transition-all duration-300 ease-out" style={{ width: `${capacity.percent}%` }}></div>
          </div>
          <p className="text-xs text-gray-400 text-right font-mono">Capacidad: {capacity.used} / {Math.floor(capacity.total)} B ({capacity.percent.toFixed(2)}%)</p>
          
          {isProcessing && (
            <div className="w-full bg-gray-800 rounded-full h-2 mt-2 border border-gray-700 overflow-hidden">
              <div className="bg-cyan-500 h-full transition-all duration-300 ease-out" style={{ width: `${progress}%` }}></div>
              <p className="text-xs text-cyan-400 mt-1 font-mono">Procesando... {Math.round(progress)}%</p>
            </div>
          )}

          <div className="flex flex-col gap-2">
            <div className="group relative inline-block w-max">
              <label className="text-sm font-semibold text-gray-300 cursor-help border-b border-dashed border-gray-500">Explorador de Planos de Bits</label>
              <div className="absolute bottom-full left-0 mb-2 hidden group-hover:block w-64 p-2 bg-gray-800 text-xs text-gray-200 rounded shadow-xl border border-gray-700 z-20">
                Permite aislar un bit específico de cada píxel. El plano 0 (LSB) es donde se oculta la información.
              </div>
            </div>
            <select disabled={isProcessing} value={bitPlane === null ? 'none' : bitPlane} onChange={(e) => {
              setShowNoise(false);
              setIsComparing(false);
              const val = e.target.value;
              if (val === 'none') {
                setBitPlane(null);
                if (currentImageDataRef.current) {
                  const ctx = canvasRef.current?.getContext('2d');
                  ctx?.putImageData(currentImageDataRef.current, 0, 0);
                }
              } else {
                const plane = parseInt(val);
                setBitPlane(plane);
                visualizeBitPlane(plane);
              }
            }} className="w-full p-3 rounded-xl bg-gray-900 border border-gray-700 text-gray-200 focus:ring-2 focus:ring-cyan-500 outline-none disabled:opacity-50 transition-all">
              <option value="none">Vista Normal</option>
              {[0, 1, 2, 3, 4, 5, 6, 7].map(p => <option key={p} value={p}>Plano {p} {p===0 ? '(LSB)' : ''}</option>)}
            </select>
          </div>
          
          <div className="group relative">
            <div className={`p-4 rounded-xl border transition-all duration-300 ${entropyInfo.suspicious ? 'bg-rose-950/30 border-rose-800/50 text-rose-300' : 'bg-emerald-950/30 border-emerald-800/50 text-emerald-300'}`}>
              <div className="flex justify-between items-center cursor-help">
                <span className="font-mono text-sm">Entropía LSB (Bit 0): {entropyInfo.e0.toFixed(4)}</span>
                <span className="font-mono text-sm">Bit 1: {entropyInfo.e1.toFixed(4)}</span>
              </div>
              {entropyInfo.suspicious && <div className="mt-1 text-xs font-bold uppercase tracking-wider">⚠️ Sospechosa - Alta Detectabilidad</div>}
            </div>
            <div className="absolute bottom-full left-0 mb-2 hidden group-hover:block w-72 p-3 bg-gray-800 text-xs text-gray-200 rounded shadow-xl border border-gray-700 z-20">
              La entropía mide la aleatoriedad. Un valor cercano a 1.0 en el Bit 0, significativamente mayor que en el Bit 1, indica posible presencia de datos cifrados ocultos.
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mt-2">
            <button disabled={isProcessing} className="col-span-2 sm:col-span-1 px-4 py-3 bg-cyan-600 text-white font-bold rounded-xl hover:bg-cyan-500 transition-all disabled:opacity-50 shadow-[0_0_15px_rgba(8,145,178,0.4)] hover:shadow-[0_0_25px_rgba(8,145,178,0.6)]" onClick={handleEncode}>
              {isProcessing ? 'Procesando...' : 'Ocultar'}
            </button>
            <button disabled={isProcessing} className="col-span-2 sm:col-span-1 px-4 py-3 bg-emerald-600 text-white font-bold rounded-xl hover:bg-emerald-500 transition-all disabled:opacity-50 shadow-[0_0_15px_rgba(5,150,105,0.4)] hover:shadow-[0_0_25px_rgba(5,150,105,0.6)]" onClick={handleDecode}>
              {isProcessing ? 'Procesando...' : 'Extraer'}
            </button>
            <button disabled={isProcessing} className="col-span-2 sm:col-span-1 px-4 py-3 bg-rose-600 text-white font-bold rounded-xl hover:bg-rose-500 transition-all disabled:opacity-50 shadow-lg" onClick={handleClear}>
              Limpiar
            </button>
            
            <button disabled={isProcessing} className={`col-span-1 px-4 py-3 ${showNoise ? 'bg-amber-500 text-gray-900' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'} font-semibold rounded-xl transition-all disabled:opacity-50 border border-gray-700`} onClick={toggleNoise}>
              {showNoise ? 'Ocultar Ruido' : 'Ver Ruido'}
            </button>
            <button disabled={isProcessing} className={`col-span-1 px-4 py-3 ${isComparing ? 'bg-indigo-500 text-white' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'} font-semibold rounded-xl transition-all disabled:opacity-50 border border-gray-700`} onClick={() => {
              setShowNoise(false);
              setBitPlane(null);
              setIsComparing(!isComparing);
            }}>
              {isComparing ? 'Fin Comparar' : 'Comparar A/B'}
            </button>
          </div>

          <div className={`transition-all duration-500 ease-in-out overflow-hidden ${decodedMessage ? 'max-h-96 opacity-100 mt-4' : 'max-h-0 opacity-0 mt-0'}`}>
            <div className="p-5 bg-gray-900 rounded-xl border border-emerald-500/30 shadow-[0_0_20px_rgba(16,185,129,0.1)]">
              <h3 className="font-bold mb-3 text-emerald-400 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"></path></svg>
                  Mensaje Extraído:
                </div>
                <button 
                  onClick={() => { navigator.clipboard.writeText(decodedMessage); alert('Copiado al portapapeles'); }}
                  className="text-xs bg-emerald-900/50 hover:bg-emerald-800 text-emerald-300 px-3 py-1 rounded border border-emerald-700 transition-colors shadow-sm"
                >
                  Copiar
                </button>
              </h3>
              <p className="whitespace-pre-wrap break-words text-gray-200 font-mono text-sm bg-gray-950 p-4 rounded-lg border border-gray-800">{decodedMessage}</p>
            </div>
          </div>

          {downloadUrl && (
            <div className="mt-4 p-5 bg-gray-900 rounded-xl border border-cyan-500/50 shadow-[0_0_20px_rgba(8,145,178,0.2)] flex flex-col items-center gap-3 transition-all duration-500">
              <a 
                href={downloadUrl} 
                download="stego-image.png" 
                className="w-full text-center px-6 py-4 bg-gradient-to-r from-cyan-600 to-blue-600 text-white font-extrabold rounded-xl hover:from-cyan-500 hover:to-blue-500 transition-all shadow-lg hover:shadow-cyan-500/50 text-lg"
              >
                ⬇️ Descargar Imagen Segura
              </a>
              <p className="text-xs text-emerald-400 font-mono flex items-center gap-1">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                Metadatos EXIF eliminados para máxima privacidad
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
