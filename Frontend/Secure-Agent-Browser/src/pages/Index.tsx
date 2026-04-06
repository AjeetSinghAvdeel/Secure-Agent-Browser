import Navbar from "@/components/Navbar";
import HeroSection from "@/components/HeroSection";
import DomeGallery from "@/components/DomeGallery";
import LiveSystemSection from "@/components/LiveSystemSection";
import HowItWorks from "@/components/HowItWorks";
import FeaturesSection from "@/components/FeaturesSection";
import TechStackSection from "@/components/TechStackSection";
import Footer from "@/components/Footer";

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <HeroSection />
      <DomeGallery />
      <LiveSystemSection />
      <HowItWorks />
      <FeaturesSection />
      <TechStackSection />
      <Footer />
    </div>
  );
};

export default Index;
