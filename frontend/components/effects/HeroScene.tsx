'use client'

import { useRef } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { Float, AdaptiveDpr, PerformanceMonitor } from '@react-three/drei'
import { EffectComposer, Bloom } from '@react-three/postprocessing'
import type { MotionValue } from 'framer-motion'
import * as THREE from 'three'
import { usePerfProfile, useInViewport } from '@/lib/usePerf'

/* ── Floating 3D objects that populate the hero background ── */
const OBJECTS = [
  /* position,            scale, geo,   color,     float speed */
  { p: [ 2.6,  0.4,  0.0], s: 0.58, g: 'hex',  c: '#FF2E97', fs: 1.4 },
  { p: [-2.5,  1.2, -1.0], s: 0.30, g: 'hex',  c: '#7A3CFF', fs: 1.0 },
  { p: [ 2.0, -1.8, -0.4], s: 0.22, g: 'oct',  c: '#FFB23E', fs: 1.6 },
  { p: [-1.6, -1.0,  0.2], s: 0.17, g: 'ico',  c: '#2DD4BF', fs: 1.2 },
  { p: [ 3.2, -0.4, -1.2], s: 0.13, g: 'oct',  c: '#FF2E97', fs: 1.8 },
  { p: [-0.6,  2.2, -0.6], s: 0.12, g: 'ico',  c: '#7A3CFF', fs: 0.9 },
  { p: [ 0.8, -2.4, -0.8], s: 0.10, g: 'hex',  c: '#FFB23E', fs: 1.5 },
  { p: [-3.2, -0.8, -0.5], s: 0.14, g: 'oct',  c: '#FF2E97', fs: 1.1 },
]

function SceneObject({ p, s, g, c, fs, animate }: typeof OBJECTS[0] & { animate: boolean }) {
  return (
    <Float
      speed={animate ? fs : 0}
      floatIntensity={animate ? 0.6 : 0}
      rotationIntensity={animate ? 0.5 : 0}
    >
      <mesh position={p as [number, number, number]} scale={s}>
        {g === 'hex' && <cylinderGeometry args={[1, 1, 0.5, 6, 1]} />}
        {g === 'oct' && <octahedronGeometry args={[1, 0]} />}
        {g === 'ico' && <icosahedronGeometry args={[1, 0]} />}
        <meshStandardMaterial
          color={c} metalness={0.78} roughness={0.14}
          emissive={c} emissiveIntensity={0.45}
          flatShading toneMapped={false}
        />
      </mesh>
    </Float>
  )
}

function SceneMesh({ mouseX, mouseY, animate, objects }: {
  mouseX: MotionValue<number>
  mouseY: MotionValue<number>
  animate: boolean
  objects: typeof OBJECTS
}) {
  const groupRef = useRef<THREE.Group>(null)

  useFrame(() => {
    if (!groupRef.current || !animate) return
    groupRef.current.rotation.x +=
      (mouseY.get() * 0.15 - groupRef.current.rotation.x) * 0.03
    groupRef.current.rotation.y +=
      (mouseX.get() * 0.2 - groupRef.current.rotation.y) * 0.03
  })

  return (
    <group ref={groupRef}>
      {objects.map((o, i) => <SceneObject key={i} {...o} animate={animate} />)}
    </group>
  )
}

export default function HeroScene({ mouseX, mouseY }: {
  mouseX: MotionValue<number>
  mouseY: MotionValue<number>
}) {
  const { prefersReducedMotion, isLowPower } = usePerfProfile()
  const { ref, visible } = useInViewport<HTMLDivElement>('150px')

  // Low-power devices render fewer objects; reduced-motion freezes the float.
  const objects = isLowPower ? OBJECTS.slice(0, 5) : OBJECTS
  const animate = !prefersReducedMotion
  const enableBloom = !isLowPower

  return (
    <div ref={ref} className="w-full h-full">
      <Canvas
        frameloop={visible && animate ? 'always' : 'demand'}
        camera={{ position: [0, 0, 6.5], fov: 56 }}
        gl={{ alpha: true, antialias: !isLowPower, powerPreference: 'high-performance' }}
        dpr={isLowPower ? [1, 1.5] : [1, 2]}
        style={{ background: 'transparent', width: '100%', height: '100%' }}
      >
        <ambientLight intensity={0.04} />
        <pointLight position={[ 5,  5,  5]} intensity={2.4} color="#FF2E97" />
        <pointLight position={[-5, -3,  3]} intensity={1.8} color="#7A3CFF" />
        <pointLight position={[ 0,  0, -5]} intensity={0.9} color="#FFB23E" />
        <SceneMesh mouseX={mouseX} mouseY={mouseY} animate={animate} objects={objects} />
        {enableBloom && (
          <EffectComposer>
            <Bloom
              intensity={1.8}
              luminanceThreshold={0.18}
              luminanceSmoothing={0.88}
              mipmapBlur
            />
          </EffectComposer>
        )}
        <PerformanceMonitor />
        <AdaptiveDpr pixelated />
      </Canvas>
    </div>
  )
}
