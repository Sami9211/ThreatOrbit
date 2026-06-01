'use client'

import { useRef } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { EffectComposer, Bloom } from '@react-three/postprocessing'
import type { MotionValue } from 'framer-motion'
import * as THREE from 'three'

/* ── Ring config ── */
const RING_R = 1.85  // torus major radius
const TUBE   = 0.022  // torus tube radius

type RingDef = { rot: [number, number, number]; color: string; speed: number }

const RINGS: RingDef[] = [
  /* plane rotation,                          color,     spin speed */
  { rot: [0,              0,            0], color: '#FF2E97', speed:  0.55 },
  { rot: [Math.PI / 2,    0,            0], color: '#7A3CFF', speed: -0.38 },
  { rot: [Math.PI * 0.35, Math.PI * 0.4, 0], color: '#FFB23E', speed:  0.46 },
]

/* ── Single torus ring + riding node ── */
function Ring({ rot, color, speed }: RingDef) {
  const spinRef = useRef<THREE.Group>(null)

  useFrame((_, dt) => {
    if (spinRef.current) spinRef.current.rotation.z += dt * speed
  })

  return (
    <group rotation={rot}>
      <group ref={spinRef}>
        <mesh>
          <torusGeometry args={[RING_R, TUBE, 20, 128]} />
          <meshStandardMaterial
            color={color} emissive={color}
            emissiveIntensity={1.4} toneMapped={false}
          />
        </mesh>
        {/* glowing node riding the ring's edge */}
        <mesh position={[RING_R, 0, 0]}>
          <sphereGeometry args={[0.085, 16, 16]} />
          <meshStandardMaterial
            color={color} emissive={color}
            emissiveIntensity={5} toneMapped={false}
          />
        </mesh>
      </group>
    </group>
  )
}

/* ── Full orbital (rings + hex, scroll + mouse reactive) ── */
function Orbital({ scrollY, mouseX, mouseY }: {
  scrollY: MotionValue<number>
  mouseX:  MotionValue<number>
  mouseY:  MotionValue<number>
}) {
  const groupRef = useRef<THREE.Group>(null)
  const hexRef   = useRef<THREE.Mesh>(null)

  useFrame((_, dt) => {
    if (!groupRef.current) return
    /* scroll drives Y rotation of the whole cluster */
    groupRef.current.rotation.y = (scrollY.get() * Math.PI) / 180
    /* mouse tilts X and Z gently */
    groupRef.current.rotation.x +=
      (mouseY.get() * 0.55 - groupRef.current.rotation.x) * 0.06
    groupRef.current.rotation.z +=
      (mouseX.get() * -0.3 - groupRef.current.rotation.z) * 0.06
    /* hex spins on its own Y axis */
    if (hexRef.current) hexRef.current.rotation.y += dt * 0.38
  })

  return (
    <group ref={groupRef}>
      {RINGS.map((r, i) => <Ring key={i} {...r} />)}

      {/* central hexagonal prism */}
      <mesh ref={hexRef}>
        <cylinderGeometry args={[0.44, 0.44, 0.26, 6, 1]} />
        <meshStandardMaterial
          color="#FF2E97" metalness={0.88} roughness={0.08}
          emissive="#7A3CFF" emissiveIntensity={0.55}
          flatShading toneMapped={false}
        />
      </mesh>
    </group>
  )
}

/* ── Canvas export ── */
export default function OrbitalScene({ scrollY, mouseX, mouseY }: {
  scrollY: MotionValue<number>
  mouseX:  MotionValue<number>
  mouseY:  MotionValue<number>
}) {
  return (
    <Canvas
      camera={{ position: [0, 1.4, 5.6], fov: 44 }}
      gl={{ alpha: true, antialias: true }}
      dpr={[1, 2]}
      style={{ background: 'transparent', width: '100%', height: '100%' }}
    >
      <ambientLight intensity={0.06} />
      <pointLight position={[4,  4, 4]}  intensity={1.8} color="#FF2E97" />
      <pointLight position={[-4, -2, 2]} intensity={1.2} color="#7A3CFF" />
      <Orbital scrollY={scrollY} mouseX={mouseX} mouseY={mouseY} />
      <EffectComposer>
        <Bloom
          intensity={2.2}
          luminanceThreshold={0.12}
          luminanceSmoothing={0.88}
          mipmapBlur
        />
      </EffectComposer>
    </Canvas>
  )
}
