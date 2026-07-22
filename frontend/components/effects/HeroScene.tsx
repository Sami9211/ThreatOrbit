'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { AdaptiveDpr, PerformanceMonitor, PointMaterial } from '@react-three/drei'
import { EffectComposer, Bloom } from '@react-three/postprocessing'
import type { MotionValue } from 'framer-motion'
import * as THREE from 'three'
import { usePerfProfile, useInViewport, clampDelta } from '@/lib/usePerf'
import ScenePlaceholder from '@/components/effects/ScenePlaceholder'

/* -- Floating solid objects --
   Hex prisms are tilted to present their hexagonal face to the camera:
   Float's rotation wobble is bounded, so without an initial tilt a prism
   can sit edge-on and read as a solid rectangle ("a box"). */
const HEX_ROT: [number, number, number] = [Math.PI / 2.3, 0.15, Math.PI / 6]
const OBJECTS: Array<{
  p: number[]; s: number; g: string; c: string; fs: number; wire: boolean
  r?: [number, number, number]
}> = [
  { p: [ 2.7,  0.5,  0.0], s: 0.62, g: 'hex',  c: '#FF2E97', fs: 1.4, wire: false, r: HEX_ROT },
  { p: [-2.7,  1.2, -1.0], s: 0.34, g: 'hex',  c: '#7A3CFF', fs: 1.0, wire: true,  r: [Math.PI / 2.6, -0.2, 0.4] },
  { p: [ 2.1, -1.9, -0.4], s: 0.26, g: 'oct',  c: '#FFB23E', fs: 1.6, wire: false },
  { p: [-1.7, -1.1,  0.3], s: 0.20, g: 'ico',  c: '#2DD4BF', fs: 1.2, wire: false },
  { p: [ 3.4, -0.5, -1.2], s: 0.15, g: 'oct',  c: '#FF2E97', fs: 1.8, wire: true  },
  { p: [-0.7,  2.3, -0.6], s: 0.14, g: 'ico',  c: '#7A3CFF', fs: 0.9, wire: false },
  { p: [ 0.9, -2.5, -0.8], s: 0.12, g: 'hex',  c: '#FFB23E', fs: 1.5, wire: false, r: [Math.PI / 2.1, 0.3, -0.3] },
  { p: [-3.4, -0.8, -0.5], s: 0.17, g: 'oct',  c: '#FF2E97', fs: 1.1, wire: true  },
  { p: [ 1.4,  2.0, -1.4], s: 0.13, g: 'ico',  c: '#2DD4BF', fs: 1.3, wire: false },
  { p: [-2.0,  0.1, -1.6], s: 0.11, g: 'hex',  c: '#7A3CFF', fs: 1.7, wire: true,  r: [Math.PI / 2.4, -0.35, 0.2] },
]

/* Pause-safe float: drei's <Float> wobbles on the ABSOLUTE clock, which keeps
   running while the render loop is paused (off-screen / mid-scroll `demand`),
   so every resume snapped objects to a new phase - the "hero moves
   unexpectedly when scrolling back to top" audit finding. This accumulates
   its own clamped-local time instead: a resume continues from the frozen pose. */
function PausableFloat({ speed, floatIntensity, rotationIntensity, children }: {
  speed: number; floatIntensity: number; rotationIntensity: number
  children: React.ReactNode
}) {
  const ref = useRef<THREE.Group>(null)
  const t = useRef(Math.random() * 100)  // random phase so objects de-sync
  useFrame((_, dt) => {
    const g = ref.current
    if (!g || speed === 0) return
    t.current += clampDelta(dt) * speed
    const tt = t.current
    g.position.y = Math.sin(tt) * 0.1 * floatIntensity
    g.rotation.x = Math.sin(tt * 0.8) * 0.07 * rotationIntensity
    g.rotation.y = Math.cos(tt * 0.6) * 0.07 * rotationIntensity
    g.rotation.z = Math.sin(tt * 0.5) * 0.07 * rotationIntensity
  })
  return <group ref={ref}>{children}</group>
}

function SceneObject({ p, s, g, c, fs, wire, r, animate, bright }: typeof OBJECTS[0] & { animate: boolean; bright: boolean }) {
  // bright=true means bloom is off (mobile/degraded). A flat unlit material
  // there rendered every solid as a featureless filled silhouette - hex prisms
  // literally read as boxes. Keep the shaded material in both modes and lean
  // on a directional key light (added by the parent when bloom is off) so the
  // facets stay visible; bump the emissive so nothing goes murky.
  const emissiveIntensity = bright ? (wire ? 1.2 : 0.6) : (wire ? 0.9 : 0.45)
  return (
    <PausableFloat speed={animate ? fs : 0} floatIntensity={0.7} rotationIntensity={0.6}>
      <mesh position={p as [number, number, number]} scale={s} rotation={r ?? [0, 0, 0]}>
        {g === 'hex' && <cylinderGeometry args={[1, 1, 0.5, 6, 1]} />}
        {g === 'oct' && <octahedronGeometry args={[1, 0]} />}
        {g === 'ico' && <icosahedronGeometry args={[1, 0]} />}
        <meshStandardMaterial
          color={c} metalness={0.78} roughness={0.14}
          emissive={c} emissiveIntensity={emissiveIntensity}
          wireframe={wire} flatShading toneMapped={false}
        />
      </mesh>
    </PausableFloat>
  )
}

/* -- Large slow-drifting wireframe torus knot for depth -- */
function BackdropKnot({ animate }: { animate: boolean }) {
  const ref = useRef<THREE.Mesh>(null)
  useFrame((_, dt) => {
    if (ref.current && animate) {
      const d = clampDelta(dt)
      ref.current.rotation.x += d * 0.04
      ref.current.rotation.y += d * 0.06
    }
  })
  return (
    <mesh ref={ref} position={[0, 0, -3]} scale={2.4}>
      <torusKnotGeometry args={[1, 0.18, 64, 12]} />
      <meshStandardMaterial
        color="#7A3CFF" emissive="#7A3CFF" emissiveIntensity={0.4}
        wireframe transparent opacity={0.12} toneMapped={false}
      />
    </mesh>
  )
}

/* -- Distant starfield -- */
function Stars({ count }: { count: number }) {
  const positions = useMemo(() => {
    const arr = new Float32Array(count * 3)
    for (let i = 0; i < count; i++) {
      arr[i * 3]     = (Math.random() - 0.5) * 16
      arr[i * 3 + 1] = (Math.random() - 0.5) * 12
      arr[i * 3 + 2] = -3 - Math.random() * 6
    }
    return arr
  }, [count])
  return (
    <points>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      {/* PointMaterial = round points; raw pointsMaterial renders squares */}
      <PointMaterial size={0.03} color="#B4A8C8" transparent opacity={0.5} sizeAttenuation depthWrite={false} />
    </points>
  )
}

function SceneMesh({ mouseX, mouseY, animate, objects, bright }: {
  mouseX: MotionValue<number>
  mouseY: MotionValue<number>
  animate: boolean
  objects: typeof OBJECTS
  bright: boolean
}) {
  const groupRef = useRef<THREE.Group>(null)
  useFrame(() => {
    if (!groupRef.current || !animate) return
    groupRef.current.rotation.x += (mouseY.get() * 0.15 - groupRef.current.rotation.x) * 0.03
    groupRef.current.rotation.y += (mouseX.get() * 0.2 - groupRef.current.rotation.y) * 0.03
  })
  return (
    <group ref={groupRef}>
      {objects.map((o, i) => <SceneObject key={i} {...o} animate={animate} bright={bright} />)}
    </group>
  )
}

export default function HeroScene({ mouseX, mouseY }: {
  mouseX: MotionValue<number>
  mouseY: MotionValue<number>
}) {
  const { prefersReducedMotion, isLowPower } = usePerfProfile()
  // Mount the canvas just before it scrolls into view, then KEEP it mounted
  // (the `mounted` latch). Tearing the WebGL context down on every scroll-away
  // and rebuilding it on scroll-back caused a blank frame - the object/orbit
  // briefly vanishing on a sudden scroll. Instead we keep one context alive and
  // only pause the render loop (`frameloop: demand`) while it is off-screen, so
  // the last frame stays on screen with zero GPU cost.
  const { ref, visible } = useInViewport<HTMLDivElement>('600px')
  const [mounted, setMounted] = useState(false)
  useEffect(() => { if (visible) setMounted(true) }, [visible])
  const [degraded, setDegraded] = useState(false)
  // NOTE: no pause-while-scrolling. An earlier version froze the loop during
  // scroll to save frame time, but frozen shapes mid-scroll read as broken
  // ("everything stops until I let go"). Cost is managed by the dpr cap +
  // AdaptiveDpr + PerformanceMonitor degradation instead, and off-screen
  // scenes still pause via `visible`.

  const objects   = isLowPower ? OBJECTS.slice(0, 6) : OBJECTS
  const animate   = !prefersReducedMotion
  const bloomOn   = !isLowPower && !degraded
  const bright    = !bloomOn   // brighten emissive when bloom can't carry the glow
  const starCount = isLowPower ? 50 : 120
  // Cap dpr at 1.75: phones (dpr≈3) stay sharp, and on retina desktops the
  // step down from 2 is invisible while cutting bloom pixel work ~23% - the
  // budget that keeps the loop running during scroll without jank.
  const dpr: [number, number] | number = degraded ? 1 : [1, 1.75]

  return (
    <div ref={ref} className="w-full h-full">
      {mounted ? (
        <Canvas
          frameloop={animate && visible ? 'always' : 'demand'}
          camera={{ position: [0, 0, 6.5], fov: 56 }}
          gl={{ alpha: true, antialias: false, powerPreference: 'high-performance' }}
          dpr={dpr}
          style={{ background: 'transparent', width: '100%', height: '100%' }}
        >
          <ambientLight intensity={0.06} />
          <pointLight position={[ 5,  5,  5]} intensity={2.6} color="#FF2E97" />
          <pointLight position={[-5, -3,  3]} intensity={2.0} color="#7A3CFF" />
          <pointLight position={[ 0,  0, -5]} intensity={1.0} color="#FFB23E" />
          {/* bloom-off fallback: distance decay leaves the point lights weak,
             so a directional key light keeps the facet shading readable */}
          {bright && <directionalLight position={[4, 5, 6]} intensity={1.6} color="#FFFFFF" />}
          <Stars count={starCount} />
          <BackdropKnot animate={animate} />
          <SceneMesh mouseX={mouseX} mouseY={mouseY} animate={animate} objects={objects} bright={bright} />
          {bloomOn && (
            <EffectComposer>
              <Bloom intensity={1.5} luminanceThreshold={0.2} luminanceSmoothing={0.85} mipmapBlur />
            </EffectComposer>
          )}
          <PerformanceMonitor onDecline={() => setDegraded(true)} />
          <AdaptiveDpr />
        </Canvas>
      ) : (
        <ScenePlaceholder />
      )}
    </div>
  )
}
