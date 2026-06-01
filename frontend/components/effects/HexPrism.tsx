'use client'

import { useRef } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import type { MotionValue } from 'framer-motion'
import * as THREE from 'three'

function Prism({
  scrollY,
  mouseX,
  mouseY,
}: {
  scrollY: MotionValue<number>
  mouseX: MotionValue<number>
  mouseY: MotionValue<number>
}) {
  const meshRef = useRef<THREE.Mesh>(null)

  useFrame(() => {
    if (!meshRef.current) return
    const deg  = scrollY.get()
    const mx   = mouseX.get()
    const my   = mouseY.get()
    meshRef.current.rotation.y = (deg * Math.PI) / 180
    // subtle mouse-reactive tilt on top of the scroll rotation
    meshRef.current.rotation.x = 0.28 + my * 0.4
    meshRef.current.rotation.z = mx * -0.2
  })

  return (
    <mesh ref={meshRef}>
      {/* CylinderGeometry with 6 segments = hexagonal prism */}
      <cylinderGeometry args={[1, 1, 0.52, 6, 1]} />
      <meshStandardMaterial
        color={new THREE.Color('#CC1870')}
        metalness={0.82}
        roughness={0.12}
        emissive={new THREE.Color('#5A1ACC')}
        emissiveIntensity={0.45}
        flatShading
      />
    </mesh>
  )
}

export default function HexPrism({
  scrollY,
  mouseX,
  mouseY,
}: {
  scrollY: MotionValue<number>
  mouseX: MotionValue<number>
  mouseY: MotionValue<number>
}) {
  return (
    <Canvas
      camera={{ position: [0, 1.4, 3.2], fov: 46 }}
      gl={{ alpha: true, antialias: true }}
      style={{ background: 'transparent', width: '100%', height: '100%' }}
    >
      {/* Key light — magenta upper-right */}
      <pointLight position={[3, 4, 3]}  intensity={5}   color="#FF2E97" />
      {/* Fill light — violet left */}
      <pointLight position={[-3, -1, 2]} intensity={2.5} color="#7A3CFF" />
      {/* Rim light — amber from behind */}
      <pointLight position={[0, -2, -3]} intensity={1.2} color="#FFB23E" />
      {/* Soft ambient so dark faces aren't black */}
      <ambientLight intensity={0.18} />
      <Prism scrollY={scrollY} mouseX={mouseX} mouseY={mouseY} />
    </Canvas>
  )
}
