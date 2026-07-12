'use client'

import { useMemo, useRef } from 'react'
import { useFrame } from '@react-three/fiber'
import * as THREE from 'three'

/**
 * Round point-sprite cloud: crisp circular dots at ANY on-screen size, because
 * a fragment shader discards fragments outside the circle. Small sphere *meshes*
 * (sphereGeometry) alias into squares at sub-pixel size — and antialiasing can't
 * save them when the scene renders through a bloom EffectComposer pass, which
 * bypasses the canvas MSAA. Points sidestep both problems.
 *
 * Per-point colour + size, plus an optional GPU-side pulse (per-point phase, so
 * dots breathe out of sync) driven entirely by a uniform — no per-frame JS over
 * the node list.
 */
export default function RoundPoints({
  positions, colors, sizes, pulse = false, pulseAmp = 0.18, pulseSpeed = 1.4,
  opacity = 1, sizeScale = 400,
}: {
  positions: Float32Array   // n*3, world space
  colors: Float32Array      // n*3, 0..1
  sizes: Float32Array       // n, world units (sizeAttenuation applies)
  pulse?: boolean
  pulseAmp?: number
  pulseSpeed?: number
  opacity?: number
  /** world-size -> screen-px factor for sizeAttenuation; tune per scene camera */
  sizeScale?: number
}) {
  const matRef = useRef<THREE.ShaderMaterial>(null)
  const n = sizes.length

  const phases = useMemo(() => {
    const a = new Float32Array(n)
    for (let i = 0; i < n; i++) a[i] = Math.random() * Math.PI * 2
    return a
  }, [n])

  const uniforms = useMemo(() => ({
    uTime: { value: 0 },
    uPulseAmp: { value: pulse ? pulseAmp : 0 },
    uPulseSpeed: { value: pulseSpeed },
    uOpacity: { value: opacity },
    // px reference for sizeAttenuation (world size -> screen px at unit depth)
    uScale: { value: sizeScale },
  }), [pulse, pulseAmp, pulseSpeed, opacity, sizeScale])

  useFrame(({ clock }) => {
    if (matRef.current) matRef.current.uniforms.uTime.value = clock.elapsedTime
  })

  return (
    <points>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
        <bufferAttribute attach="attributes-aColor" args={[colors, 3]} />
        <bufferAttribute attach="attributes-size" args={[sizes, 1]} />
        <bufferAttribute attach="attributes-phase" args={[phases, 1]} />
      </bufferGeometry>
      <shaderMaterial
        ref={matRef}
        uniforms={uniforms}
        transparent
        depthWrite={false}
        vertexShader={`
          attribute vec3 aColor;
          attribute float size;
          attribute float phase;
          varying vec3 vColor;
          uniform float uTime;
          uniform float uPulseAmp;
          uniform float uPulseSpeed;
          uniform float uScale;
          void main() {
            vColor = aColor;
            float s = size * (1.0 + uPulseAmp * sin(uTime * uPulseSpeed + phase));
            vec4 mv = modelViewMatrix * vec4(position, 1.0);
            gl_PointSize = s * (uScale / -mv.z);
            gl_Position = projectionMatrix * mv;
          }
        `}
        fragmentShader={`
          varying vec3 vColor;
          uniform float uOpacity;
          void main() {
            vec2 c = gl_PointCoord - 0.5;
            float d = dot(c, c);
            if (d > 0.25) discard;               // hard circle edge
            float a = smoothstep(0.25, 0.14, d); // soft anti-aliased rim
            gl_FragColor = vec4(vColor, a * uOpacity);
          }
        `}
      />
    </points>
  )
}
