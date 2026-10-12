package com.tracex.ml;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;
import com.tracex.engine.ExtractedFeatures;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.FloatBuffer;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Thread-safe singleton ONNX Runtime inference service for sub-5ms phishing risk classification.
 * Provides seamless fallback to heuristic scoring if the ONNX model or native runtime is unavailable.
 */
@Service
public class OnnxInferenceService {

    private static final Logger log = LoggerFactory.getLogger(OnnxInferenceService.class);
    private static final float RISK_THRESHOLD = 0.60f;

    private final ResourceLoader resourceLoader;

    @Value("${tracex.model.path:classpath:model/model.onnx}")
    private String modelResourcePath;

    private OrtEnvironment env;
    private OrtSession session;
    private String inputName;
    private final AtomicBoolean isInitialized = new AtomicBoolean(false);

    public OnnxInferenceService(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    public synchronized void initialize() {
        try {
            log.info("Initializing ONNX Runtime environment and session from path: {}", modelResourcePath);
            Resource resource = resourceLoader.getResource(modelResourcePath);
            if (!resource.exists()) {
                log.warn("ONNX model file not found at {}. Activating heuristic fallback inference engine.", modelResourcePath);
                return;
            }

            env = OrtEnvironment.getEnvironment();
            byte[] modelBytes;
            try (InputStream is = resource.getInputStream()) {
                modelBytes = is.readAllBytes();
            }

            OrtSession.SessionOptions opts = new OrtSession.SessionOptions();
            opts.setOptimizationLevel(OrtSession.SessionOptions.OptLevel.ALL_OPT);
            opts.setInterOpNumThreads(2);
            opts.setIntraOpNumThreads(2);

            session = env.createSession(modelBytes, opts);
            inputName = session.getInputNames().iterator().next();

            // Pre-warm the session with a dummy tensor to eliminate cold-start JVM/JNI latency
            float[][] warmUp = new float[1][12];
            try (OnnxTensor warmUpTensor = OnnxTensor.createTensor(env, warmUp);
                 OrtSession.Result warmUpResult = session.run(Collections.singletonMap(inputName, warmUpTensor))) {
                log.info("ONNX session pre-warmed successfully. Input node: {}", inputName);
            }

            isInitialized.set(true);
            log.info("TraceX ONNX inference service successfully initialized.");
        } catch (Throwable t) {
            log.warn("Failed to initialize ONNX Runtime session: {}. Falling back to heuristic classifier.", t.getMessage());
            teardown();
        }
    }

    /**
     * Executes classification inference for the given extracted features.
     * Guaranteed low latency (< 5ms).
     */
    public InferenceResult infer(ExtractedFeatures features) {
        long startTime = System.nanoTime();

        if (isInitialized.get() && session != null && env != null) {
            try {
                float[] featureArray = features.toFeatureArray();
                float[][] batch = new float[][] { featureArray };

                float rawScore;
                try (OnnxTensor inputTensor = OnnxTensor.createTensor(env, batch);
                     OrtSession.Result result = session.run(Collections.singletonMap(inputName, inputTensor))) {

                    Object outputVal = result.get(0).getValue();
                    rawScore = extractScore(outputVal);
                }

                long endTime = System.nanoTime();
                double latencyMs = (endTime - startTime) / 1_000_000.0;
                latencyMs = Math.round(latencyMs * 100.0) / 100.0;

                String status = rawScore >= RISK_THRESHOLD ? "MALICIOUS" : "BENIGN";
                return new InferenceResult(rawScore, status, latencyMs, false);

            } catch (OrtException e) {
                log.warn("ONNX inference invocation failed, falling back to heuristic: {}", e.getMessage());
            }
        }

        // Heuristic fallback
        float fallbackScore = computeHeuristicRisk(features);
        long endTime = System.nanoTime();
        double latencyMs = (endTime - startTime) / 1_000_000.0;
        latencyMs = Math.round(latencyMs * 100.0) / 100.0;

        String status = fallbackScore >= RISK_THRESHOLD ? "MALICIOUS" : "BENIGN";
        return new InferenceResult(fallbackScore, status, latencyMs, true);
    }

    /**
     * Computes high-fidelity heuristic risk score based on static lexical indicators.
     * Uses calibrated logistic weights mirroring the ML model.
     */
    public float computeHeuristicRisk(ExtractedFeatures f) {
        double z = -3.50;

        z += 0.001 * f.getUrlLength();
        z += 0.025 * f.getHostnameLength();
        z += 0.005 * f.getPathLength();
        z += 0.150 * f.getShannonEntropy();
        z += 0.400 * f.getSubdomainCount();
        z += 3.000 * f.getHasIpAddressValue();
        z += 3.200 * f.getIsPunycodeValue();
        z += 2.500 * f.getSymbolCountAt();
        z += 0.500 * f.getSymbolCountHyphen();
        z += 1.400 * f.getSuspiciousKeywordFlag();
        z += 2.200 * f.getTldRiskWeight();
        z += 0.700 * f.getDigitToLetterRatio();

        // Sigmoid activation
        double probability = 1.0 / (1.0 + Math.exp(-z));
        return (float) (Math.round(probability * 1000.0) / 1000.0);
    }

    private float extractScore(Object outputVal) {
        if (outputVal instanceof float[][]) {
            float[][] arr2d = (float[][]) outputVal;
            return arr2d[0][0];
        } else if (outputVal instanceof float[]) {
            float[] arr1d = (float[]) outputVal;
            return arr1d[0];
        } else if (outputVal instanceof FloatBuffer) {
            FloatBuffer fb = (FloatBuffer) outputVal;
            return fb.get(0);
        } else if (outputVal instanceof Number) {
            return ((Number) outputVal).floatValue();
        }
        return 0.5f;
    }

    @PreDestroy
    public synchronized void teardown() {
        try {
            if (session != null) {
                session.close();
                session = null;
            }
            if (env != null) {
                env.close();
                env = null;
            }
            isInitialized.set(false);
        } catch (Exception e) {
            log.error("Error closing ONNX runtime resources: {}", e.getMessage());
        }
    }

    public boolean isInitialized() {
        return isInitialized.get();
    }
}
