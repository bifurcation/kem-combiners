pub mod base;
pub mod combiners;
pub mod hybrid;

#[cfg(test)]
#[generic_tests::define]
mod tests {
    use crate::base::*;
    use crate::combiners::*;
    use crate::hybrid::*;

    fn key_pair<T, PQ>() -> (DecapsulationKey<T, PQ>, EncapsulationKey<T, PQ>)
    where
        T: BaseKem,
        PQ: BaseKem,
    {
        let mut rng = rand::thread_rng();
        HybridKem::generate(&mut rng)
    }

    fn test_encap_decap<T, PQ, C>(c: &C, dk: DecapsulationKey<T, PQ>, ek: EncapsulationKey<T, PQ>)
    where
        T: BaseKem,
        PQ: BaseKem,
        C: Combiner,
    {
        let mut rng = rand::thread_rng();
        let (ct, ss_e) = HybridKem::encap(c, &mut rng, &ek);
        let ss_d = HybridKem::decap(c, &dk, &ct);
        assert_eq!(ss_e, ss_d);
    }

    #[test]
    fn kitchen_sink<T, PQ>()
    where
        T: BaseKem,
        PQ: BaseKem,
    {
        let (dk, ek) = key_pair::<T, PQ>();
        test_encap_decap(&KitchenSink, dk, ek);
    }

    #[test]
    fn kitchen_sink_pre<T, PQ>()
    where
        T: BaseKem,
        PQ: BaseKem,
    {
        let (dk, ek) = key_pair::<T, PQ>();
        let kitchen_sink_pre = KitchenSinkPre::new_hybrid(&ek);
        test_encap_decap(&kitchen_sink_pre, dk, ek);
    }

    #[test]
    fn kitchen_sink_pre_eq<T, PQ>()
    where
        T: BaseKem,
        PQ: BaseKem,
    {
        let (dk, ek) = key_pair::<T, PQ>();
        let kitchen_sink = KitchenSink;
        let kitchen_sink_pre = KitchenSinkPre::new_hybrid(&ek);

        let mut rng = rand::thread_rng();
        let (ct, ss_e) = HybridKem::encap(&kitchen_sink, &mut rng, &ek);
        let ss_d = HybridKem::decap(&kitchen_sink_pre, &dk, &ct);
        assert_eq!(ss_e, ss_d);

        let mut rng = rand::thread_rng();
        let (ct, ss_e) = HybridKem::encap(&kitchen_sink_pre, &mut rng, &ek);
        let ss_d = HybridKem::decap(&kitchen_sink, &dk, &ct);
        assert_eq!(ss_e, ss_d);
    }

    #[test]
    fn chempat<T, PQ>()
    where
        T: BaseKem,
        PQ: BaseKem,
    {
        let (dk, ek) = key_pair::<T, PQ>();
        test_encap_decap(&Chempat, dk, ek);
    }

    #[test]
    fn chempat_pre<T, PQ>()
    where
        T: BaseKem,
        PQ: BaseKem,
    {
        let (dk, ek) = key_pair::<T, PQ>();
        let chempat_pre = ChempatPre::new_hybrid(&ek);
        test_encap_decap(&chempat_pre, dk, ek);
    }

    #[test]
    fn chempat_pre_eq<T, PQ>()
    where
        T: BaseKem,
        PQ: BaseKem,
    {
        let (dk, ek) = key_pair::<T, PQ>();
        let chempat = Chempat;
        let chempat_pre = ChempatPre::new_hybrid(&ek);

        let mut rng = rand::thread_rng();
        let (ct, ss_e) = HybridKem::encap(&chempat, &mut rng, &ek);
        let ss_d = HybridKem::decap(&chempat_pre, &dk, &ct);
        assert_eq!(ss_e, ss_d);

        let mut rng = rand::thread_rng();
        let (ct, ss_e) = HybridKem::encap(&chempat_pre, &mut rng, &ek);
        let ss_d = HybridKem::decap(&chempat, &dk, &ct);
        assert_eq!(ss_e, ss_d);
    }

    #[test]
    fn dhkem<T, PQ>()
    where
        T: BaseKem,
        PQ: BaseKem,
    {
        let (dk, ek) = key_pair::<T, PQ>();
        test_encap_decap(&Dhkem, dk, ek);
    }

    #[test]
    fn dhkem_pre<T, PQ>()
    where
        T: BaseKem,
        PQ: BaseKem,
    {
        let (dk, ek) = key_pair::<T, PQ>();
        let dhkem_pre = DhkemPre::new_hybrid(&ek);
        test_encap_decap(&dhkem_pre, dk, ek);
    }

    #[test]
    fn dhkem_pre_eq<T, PQ>()
    where
        T: BaseKem,
        PQ: BaseKem,
    {
        let (dk, ek) = key_pair::<T, PQ>();
        let dhkem = Dhkem;
        let dhkem_pre = DhkemPre::new_hybrid(&ek);

        let mut rng = rand::thread_rng();
        let (ct, ss_e) = HybridKem::encap(&dhkem, &mut rng, &ek);
        let ss_d = HybridKem::decap(&dhkem_pre, &dk, &ct);
        assert_eq!(ss_e, ss_d);

        let mut rng = rand::thread_rng();
        let (ct, ss_e) = HybridKem::encap(&dhkem_pre, &mut rng, &ek);
        let ss_d = HybridKem::decap(&dhkem, &dk, &ct);
        assert_eq!(ss_e, ss_d);
    }

    #[test]
    fn dhkem_half<T, PQ>()
    where
        T: BaseKem,
        PQ: BaseKem,
    {
        let (dk, ek) = key_pair::<T, PQ>();
        test_encap_decap(&DhkemHalf, dk, ek);
    }

    #[test]
    fn xwing<T, PQ>()
    where
        T: BaseKem,
        PQ: BaseKem,
    {
        let (dk, ek) = key_pair::<T, PQ>();
        test_encap_decap(&XWing, dk, ek);
    }

    #[instantiate_tests(<X25519, MlKem>)]
    mod x25519_ml_kem {}

    #[instantiate_tests(<X25519, ClassicMcEliece>)]
    mod x25519_classic_mceliece {}
}
